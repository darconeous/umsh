use super::*;
use crate::peers::RouteOffer;

/// A route as a received frame would offer it, scored as given.
fn scored(route: CachedRoute, score: i16) -> RouteOffer {
    RouteOffer {
        route,
        score: Some(score),
        supersedes: false,
        acknowledgment: false,
    }
}

#[test]
fn direct_ack_requested_exchange_stops_at_exactly_two_frames() {
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
    let receipt = scenario.macs[0]
        .borrow_mut()
        .queue_unicast(
            scenario.identity_ids[0],
            &scenario.keys[1],
            b"payload",
            &SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(10),
        )
        .unwrap()
        .unwrap();
    let mut data_transmissions = 0;
    let mut delivered = 0;
    let mut acknowledged = 0;
    let mut forward_deadline = None;
    let mut ack_deadline = 0;
    // Keep polling long after both confirmation and ACK deadlines. The ACK
    // must cancel the ladder, leaving neither queued retries nor later traffic.
    for _ in 0..6_000 {
        for (node, mac) in scenario.macs.iter().enumerate() {
            let mut mac = mac.borrow_mut();
            block_on(mac.poll_cycle(|_, event| match event {
                MacEventRef::Transmitted { wire_bytes, .. } => {
                    assert_eq!(node, 0);
                    let header = PacketHeader::parse(wire_bytes).unwrap();
                    assert_eq!(header.packet_type(), PacketType::UnicastAckReq);
                    assert_eq!(header.flood_hops, FloodHops::new(1, 0));
                    let options =
                        ParsedOptions::extract(wire_bytes, header.options_range.clone()).unwrap();
                    assert!(!options.route_retry);
                    data_transmissions += 1;
                }
                MacEventRef::AckReceived {
                    receipt: actual, ..
                } => {
                    assert_eq!(node, 0);
                    assert_eq!(actual, receipt);
                    assert!(scenario.network.clock().now_ms() < forward_deadline.unwrap());
                    acknowledged += 1;
                }
                MacEventRef::AckTimeout { .. } => panic!("direct exchange timed out"),
                _ => {
                    if node == 1 && is_received_type(&event, PacketType::Unicast) {
                        delivered += 1;
                    }
                }
            }))
            .unwrap();
            if node == 0
                && forward_deadline.is_none()
                && let Some(pending) = mac
                    .identity(scenario.identity_ids[0])
                    .unwrap()
                    .pending_ack(&receipt)
                && let AckState::AwaitingForward {
                    confirm_deadline_ms,
                } = pending.state
            {
                forward_deadline = Some(confirm_deadline_ms);
                ack_deadline = pending.ack_deadline_ms;
            }
        }
        scenario.network.advance_ms(5);
    }
    assert!(
        forward_deadline.is_some(),
        "the send entered the forwarding-confirmation wait"
    );
    assert!(scenario.network.clock().now_ms() > ack_deadline);
    assert_eq!(delivered, 1);
    assert_eq!(acknowledged, 1);
    assert_eq!(data_transmissions, 1);
    for (node, mac) in scenario.macs.iter().enumerate() {
        let mac = mac.borrow();
        // The untracked direct ACK emits no Transmitted event. The radio
        // counters include it: one request plus one ACK, with no later retries.
        assert_eq!(mac.counters().tx_frames, 1);
        assert!(mac.tx_queue().is_empty());
        assert_eq!(
            mac.identity(scenario.identity_ids[node])
                .unwrap()
                .pending_acks()
                .count(),
            0
        );
    }
}

#[test]
fn asymmetric_shortcut_completes_first_exchange_and_subsequent_bidirectional_sends() {
    for forced_route in [false, true] {
        let mut scenario = build_modeled_line_scenario(3);
        install_endpoint_pairwise_keys(&mut scenario);
        let profile = crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -80,
            base_snr: Snr::from_decibels(9), // Strong reception is still asymmetric.
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 0,
            drop_per_thousand: 0,
        };
        for (a, b) in [(0, 1), (1, 0), (1, 2), (2, 1), (0, 2)] {
            scenario.network.set_link_profile(
                scenario.radio_ids[a],
                scenario.radio_ids[b],
                profile,
            );
        }
        // Discovery must converge even when the origin has already cached a
        // direct observation. That observation is not a bidirectional link.
        {
            let mut origin = scenario.macs[0].borrow_mut();
            let (peer_id, _) = origin
                .peer_registry()
                .lookup_by_key(&scenario.keys[2])
                .unwrap();
            origin
                .peer_registry_mut()
                .update_route(peer_id, CachedRoute::Direct);
        }
        for (round, (sender, receiver)) in [(0, 2), (2, 0), (0, 2)].into_iter().enumerate() {
            let mut options = SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(2);
            if forced_route && round == 0 {
                options = options
                    .try_with_source_route(&[scenario.keys[1].router_hint()])
                    .unwrap();
            }
            // Dummy XOR crypto does not diffuse counter changes into the
            // truncated ACK tag. Distinct payloads avoid artificial ACK collisions.
            let payload = [round as u8 + 1; 13];
            let receipt = scenario.macs[sender]
                .borrow_mut()
                .queue_unicast(
                    scenario.identity_ids[sender],
                    &scenario.keys[receiver],
                    &payload,
                    &options,
                )
                .unwrap()
                .unwrap();
            let delivered = Cell::new(0);
            let acked = Cell::new(false);
            pump_modeled_until(
                &scenario.network,
                &scenario.macs,
                5,
                1_000,
                |node, _, event| match event {
                    MacEventRef::Transmitted { wire_bytes, .. } if round == 0 => {
                        let header = PacketHeader::parse(wire_bytes).unwrap();
                        let options =
                            ParsedOptions::extract(wire_bytes, header.options_range).unwrap();
                        assert!(
                            !options.route_retry,
                            "first exchange must not require route recovery"
                        );
                    }
                    MacEventRef::AckReceived {
                        receipt: actual, ..
                    } if node == sender && *actual == receipt => acked.set(true),
                    MacEventRef::AckTimeout {
                        receipt: actual, ..
                    } if node == sender && *actual == receipt => {
                        panic!("asymmetric exchange timed out: forced={forced_route} round={round}")
                    }
                    _ => {
                        if node == receiver
                            && let Some(packet) = received_of_type(event, PacketType::Unicast)
                            && packet.payload_bytes() == payload
                        {
                            delivered.set(delivered.get() + 1);
                        }
                    }
                },
                || acked.get(),
                "ACK across the asymmetric shortcut",
            );
            assert_eq!(delivered.get(), 1);
            if round == 0 {
                assert!(
                    scenario.network.clock().now_ms() < 900,
                    "first exchange must finish before route recovery"
                );
                assert_eq!(
                    scenario.macs[0]
                        .borrow()
                        .peer_registry()
                        .lookup_by_key(&scenario.keys[2])
                        .unwrap()
                        .1
                        .route,
                    CachedRoute::source(&[scenario.keys[1].router_hint()]),
                    "the ACK must replace the provisional direct observation"
                );
            }
            // Settle optional ACK forwards before starting another exchange.
            for _ in 0..100 {
                for mac in &scenario.macs {
                    block_on(mac.borrow_mut().poll_cycle(|_, _| {})).unwrap();
                }
                scenario.network.advance_ms(5);
            }
        }
    }
}

#[test]
fn unconsumed_copy_teaches_whole_route_and_consumed_duplicate_gets_first_ack() {
    let (mut mac, local_id, _, peer_id) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let original = CachedRoute::source(&[RouterHint([4, 5])]).unwrap();
    mac.peer_registry_mut()
        .update_route(peer_id, original.clone());
    let route = [RouterHint([6, 7])];
    let mut delivered = 0;
    for consumed in [false, true, true] {
        mac.radio_mut().queue_received_unicast_with_route(
            &remote,
            &keys,
            &dst,
            b"payload",
            true,
            7,
            None,
            Some(if consumed { &route } else { &[] }),
            Some(if consumed { &[] } else { &route }),
        );
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Unicast) {
                delivered += 1;
            }
        }))
        .unwrap();
        if !consumed {
            // Overheard before the last repeater consumed its hint, the copy
            // still teaches the route through that repeater, never the
            // shortcut past it.
            assert_eq!(
                mac.peer_registry().get(peer_id).unwrap().route,
                CachedRoute::source(&route)
            );
            assert_ne!(Some(original.clone()), CachedRoute::source(&route));
            assert!(mac.tx_queue().is_empty());
        }
        mac.clock().advance_ms(1);
    }
    assert_eq!(delivered, 1);
    assert_eq!(
        mac.tx_queue().len(),
        1,
        "exactly the first eligible copy is ACKed"
    );
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        CachedRoute::source(&route)
    );
}

#[test]
fn blind_unicast_also_acks_first_consumed_copy() {
    let (mut mac, local_id, _, _) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let pairwise = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let channel = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel);
    mac.add_channel(channel).unwrap();
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let route = [RouterHint([6, 7])];
    let mut delivered = 0;
    for consumed in [false, true, true] {
        mac.radio_mut().queue_received_blind_unicast_with_route(
            &remote,
            &pairwise,
            &channel_keys,
            &dst,
            b"payload",
            true,
            Some(if consumed { &[] } else { &route }),
        );
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::BlindUnicast) {
                delivered += 1;
            }
        }))
        .unwrap();
        if !consumed {
            assert!(mac.tx_queue().is_empty());
        }
        mac.clock().advance_ms(1);
    }
    assert_eq!(delivered, 1);
    assert_eq!(mac.tx_queue().len(), 1);
}

#[test]
fn ack_queue_exhaustion_does_not_consume_first_ack_opportunity() {
    let (mut mac, local_id, _, _) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    while mac
        .tx_queue_mut()
        .enqueue(TxPriority::ImmediateAck, b"occupied", None, None)
        .is_ok()
    {}
    let mut delivered = 0;
    for attempt in 0..2 {
        mac.radio_mut()
            .queue_received_unicast(&remote, &keys, &dst, b"payload", true);
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Unicast) {
                delivered += 1;
            }
        }))
        .unwrap();
        if attempt == 0 {
            while mac.tx_queue_mut().pop_next().is_some() {}
        }
    }
    assert_eq!(delivered, 1);
    assert_eq!(mac.tx_queue().len(), 1);
    assert_eq!(
        PacketHeader::parse(&mac.tx_queue_mut().pop_next().unwrap().frame)
            .unwrap()
            .packet_type(),
        PacketType::MacAck
    );
}

fn expire_attempt(mac: &mut TestMac, local_id: LocalIdentityId, receipt: SendReceipt) {
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
}

#[test]
fn route_failure_recovery_and_passive_learning_holdoff() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);
    let receipt = mac
        .queue_unicast(
            local_id,
            &key,
            b"payload",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next().unwrap();
    expire_attempt(&mut mac, local_id, receipt);
    assert!(mac.peer_registry().get(peer_id).unwrap().route.is_none());
    let retry = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(&retry.frame).unwrap();
    assert_eq!(header.flood_hops.unwrap().remaining(), 5);
    assert!(
        ParsedOptions::extract(&retry.frame, header.options_range)
            .unwrap()
            .route_retry
    );
    let now = mac.clock().now_ms();
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(CachedRoute::Direct, -10), now + 1);
    assert!(mac.peer_registry().get(peer_id).unwrap().route.is_none());
    let alternate = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(alternate.clone(), -60), now + 2);
    expire_attempt(&mut mac, local_id, receipt);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(alternate)
    );
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(CachedRoute::Direct, -10), now + 30_000);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Direct)
    );
}

#[test]
fn old_timeout_preserves_replacement_and_newer_success_of_same_route() {
    for replace in [false, true] {
        let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
        mac.peer_registry_mut()
            .update_route(peer_id, CachedRoute::Direct);
        let options = SendOptions::default().with_ack_requested(true);
        let old = mac
            .queue_unicast(local_id, &key, b"old", &options)
            .unwrap()
            .unwrap();
        let expected = if replace {
            let route = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
            mac.peer_registry_mut().update_route(peer_id, route.clone());
            route
        } else {
            let newer = mac
                .queue_unicast(local_id, &key, b"new", &options)
                .unwrap()
                .unwrap();
            let ack = mac
                .identity(local_id)
                .unwrap()
                .pending_ack(&newer)
                .unwrap()
                .ack_trailer;
            mac.complete_ack(&key, &ack).unwrap();
            CachedRoute::Direct
        };
        expire_attempt(&mut mac, local_id, old);
        assert_eq!(
            mac.peer_registry().get(peer_id).unwrap().route,
            Some(expected)
        );
    }
}

#[test]
fn explicit_route_failure_does_not_invalidate_cache_and_no_flood_stays_disabled() {
    for flood in [false, true] {
        let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
        mac.peer_registry_mut()
            .update_route(peer_id, CachedRoute::Direct);
        let mut options = SendOptions::default()
            .with_ack_requested(true)
            .try_with_source_route(&[RouterHint([1, 2])])
            .unwrap();
        if !flood {
            options = options.no_flood();
        }
        let receipt = mac
            .queue_unicast(local_id, &key, b"payload", &options)
            .unwrap()
            .unwrap();
        mac.tx_queue_mut().pop_next().unwrap();
        expire_attempt(&mut mac, local_id, receipt);
        assert_eq!(
            mac.peer_registry().get(peer_id).unwrap().route,
            Some(CachedRoute::Direct)
        );
        assert_eq!(mac.tx_queue().is_empty(), !flood);
    }
}

#[test]
fn direct_optional_backstop_does_not_retransmit_ack_or_non_ack_data() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);
    mac.queue_unicast(local_id, &key, b"reply", &SendOptions::default())
        .unwrap();
    mac.queue_mac_ack_for_peer(local_id, peer_id, [7; 8], true)
        .unwrap();
    for _ in 0..100 {
        block_on(mac.poll_cycle(|_, _| {})).unwrap();
        mac.clock().advance_ms(100);
    }
    assert_eq!(mac.radio().transmitted.len(), 2);
    assert_eq!(mac.identity(local_id).unwrap().pending_acks().count(), 0);
}

#[test]
fn matching_ack_preserves_current_outbound_route_despite_different_return_trace() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let route = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    mac.peer_registry_mut().update_route(peer_id, route.clone());
    let receipt = mac
        .queue_unicast(
            local_id,
            &key,
            b"payload",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    let ack = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_trailer;
    mac.radio_mut()
        .queue_received_mac_ack_with_trace(ack, &[RouterHint([3, 4])]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, Some(route));
}

#[test]
fn ack_trace_upgrades_direct_observations_and_next_send_names_the_repeater() {
    for cached in [
        CachedRoute::Direct,
        CachedRoute::flood(0, &[]).unwrap(),
        CachedRoute::source(&[]).unwrap(),
    ] {
        for ceiling in [1, 5] {
            let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
            mac.peer_registry_mut()
                .update_route(peer_id, cached.clone());
            let options = SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(ceiling);
            let receipt = mac
                .queue_unicast(local_id, &key, b"payload", &options)
                .unwrap()
                .unwrap();
            mac.tx_queue_mut().pop_next().unwrap();
            let ack = mac
                .identity(local_id)
                .unwrap()
                .pending_ack(&receipt)
                .unwrap()
                .ack_trailer;
            let route = [RouterHint([3, 4]), RouterHint([5, 6])];
            mac.radio_mut()
                .queue_received_mac_ack_with_trace(ack, &route);
            block_on(mac.receive_one(|_, _| {})).unwrap();
            assert_eq!(
                mac.peer_registry().get(peer_id).unwrap().route,
                CachedRoute::source(&route)
            );

            mac.queue_unicast(local_id, &key, b"next", &options)
                .unwrap();
            let queued = mac.tx_queue_mut().pop_next().unwrap();
            let header = PacketHeader::parse(&queued.frame).unwrap();
            let options = ParsedOptions::extract(&queued.frame, header.options_range).unwrap();
            assert_eq!(&queued.frame[options.source_route.unwrap()], &[3, 4, 5, 6]);
        }
    }
}

#[test]
fn older_ack_cannot_replace_a_newer_routed_path() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);
    let receipt = mac
        .queue_unicast(
            local_id,
            &key,
            b"payload",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    let ack = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_trailer;
    let replacement = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    mac.peer_registry_mut()
        .update_route(peer_id, replacement.clone());
    mac.radio_mut()
        .queue_received_mac_ack_with_trace(ack, &[RouterHint([3, 4])]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(replacement)
    );
}

#[test]
fn host_source_route_ack_tail_preserves_received_regions() {
    let (mut mac, local_id, _, _) = mac_with_keyed_peer();
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let mut buf = [0u8; 128];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_full(&test_pubkey(0xAB))
        .frame_counter(7)
        .ack_requested()
        .option(OptionNumber::TraceRoute, &[1, 2])
        .option(OptionNumber::SourceRoute, &[])
        .region_code([3, 4])
        .region_code([5, 6])
        .payload(b"payload")
        .build()
        .unwrap();
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(
            &mut packet,
            &PairwiseKeys {
                k_enc: [1; 32],
                k_mic: [2; 32],
            },
        )
        .unwrap();
    mac.radio_mut().queue_received_frame(packet.as_bytes());
    block_on(mac.receive_one(|_, _| {})).unwrap();
    let ack = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(&ack.frame).unwrap();
    assert_eq!(header.flood_hops, FloodHops::new(1, 0));
    let regions: Vec<Vec<u8>> = iter_options(&ack.frame, header.options_range)
        .filter_map(|entry| {
            let (number, value) = entry.unwrap();
            (OptionNumber::from(number) == OptionNumber::RegionCode).then(|| value.to_vec())
        })
        .collect();
    assert_eq!(regions, vec![vec![3, 4], vec![5, 6]]);
}

#[test]
fn terminal_failure_of_cached_source_route_respects_no_flood() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let route = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    mac.peer_registry_mut().update_route(peer_id, route.clone());
    let receipt = mac
        .queue_unicast(
            local_id,
            &key,
            b"payload",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next().unwrap();
    // Passive repetition of the same evidence cannot immunize a failed route.
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(route.clone(), -40), 1);
    expire_attempt(&mut mac, local_id, receipt);
    assert!(mac.peer_registry().get(peer_id).unwrap().route.is_none());
    assert!(mac.tx_queue().is_empty());
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
    // Explicit operator restoration overrides the passive-learning holdoff.
    mac.peer_registry_mut().update_route(peer_id, route.clone());
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, Some(route));
}

#[test]
fn failed_ack_requested_enqueue_does_not_invalidate_route() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);
    while mac
        .tx_queue_mut()
        .enqueue(TxPriority::ImmediateAck, b"occupied", None, None)
        .is_ok()
    {}
    assert!(
        mac.queue_unicast(
            local_id,
            &key,
            b"payload",
            &SendOptions::default().with_ack_requested(true)
        )
        .is_err()
    );
    mac.clock().advance_ms(100_000);
    mac.service_pending_ack_timeouts(|_, _| panic!("nothing transmitted"))
        .unwrap();
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Direct)
    );
}

#[test]
fn consumed_source_route_without_usable_trace_uses_broader_ack_fallback() {
    for cached in [
        None,
        Some(CachedRoute::Direct),
        CachedRoute::flood(0, &[]),
        CachedRoute::flood(2, &[]),
        CachedRoute::source(&[RouterHint([3, 4])]),
    ] {
        for accumulated in [0, 6, 15] {
            for trace in [None, Some(&[0x01][..]), Some(&[][..])] {
                let (mut mac, local_id, _, peer_id) = mac_with_keyed_peer();
                if let Some(route) = cached.clone() {
                    mac.peer_registry_mut().update_route(peer_id, route);
                }
                let dst = mac
                    .identity(local_id)
                    .unwrap()
                    .identity()
                    .public_key()
                    .hint();
                let mut buf = [0u8; 128];
                let mut builder = PacketBuilder::new(&mut buf)
                    .unicast(dst)
                    .source_full(&test_pubkey(0xAB))
                    .frame_counter(7)
                    .ack_requested();
                if let Some(trace) = trace {
                    builder = builder.option(OptionNumber::TraceRoute, trace);
                }
                let mut packet = builder
                    .flood_hops(1)
                    .option(OptionNumber::SourceRoute, &[])
                    .payload(b"payload")
                    .build()
                    .unwrap();
                CryptoEngine::new(DummyAes, DummySha)
                    .seal_packet(
                        &mut packet,
                        &PairwiseKeys {
                            k_enc: [1; 32],
                            k_mic: [2; 32],
                        },
                    )
                    .unwrap();
                packet.as_bytes_mut()[1] = FloodHops::new(1, accumulated).unwrap().0;
                mac.radio_mut().queue_received_frame(packet.as_bytes());
                block_on(mac.receive_one(|_, _| {})).unwrap();
                let ack = mac.tx_queue_mut().pop_next().unwrap();
                let header = PacketHeader::parse(&ack.frame).unwrap();
                let expected = if trace == Some(&[][..]) {
                    1
                } else {
                    match cached.as_ref() {
                        Some(CachedRoute::Source(_)) => 1,
                        Some(CachedRoute::Flood { flood_hops, .. }) if *flood_hops > 0 => {
                            flood_hops + 1
                        }
                        _ => (accumulated + 1).clamp(5, 15),
                    }
                };
                assert_eq!(header.flood_hops.unwrap().remaining(), expected);
            }
        }
    }
}

fn reply_keys() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    }
}

fn route_to(mac: &TestMac, peer_id: PeerId) -> Option<CachedRoute> {
    mac.peer_registry().get(peer_id).unwrap().route.clone()
}

/// Copies of one reply arrive over several paths. The first teaches a route
/// at once; a later copy over a clearly better path replaces it, and a
/// flood-tail copy over a worse one does not.
#[test]
fn a_better_copy_of_a_reply_replaces_the_route_and_a_worse_one_does_not() {
    let (mut mac, local_id, _, peer_id) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let (a, b, c) = (
        RouterHint([0xA1, 0xA2]),
        RouterHint([0xB1, 0xB2]),
        RouterHint([0xC1, 0xC2]),
    );

    // Barely: A heard at -12 dB here, and A heard the peer at -14 dB.
    mac.radio_mut().rx_snr = Snr::from_decibels(-12);
    mac.radio_mut()
        .queue_received_traced_unicast(&remote, &reply_keys(), &dst, 7, &[a], &[-140]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(route_to(&mac, peer_id), CachedRoute::source(&[a]));

    // The same reply through B, heard cleanly at both hops.
    mac.clock().advance_ms(50);
    mac.radio_mut().rx_snr = Snr::from_decibels(3);
    mac.radio_mut()
        .queue_received_traced_unicast(&remote, &reply_keys(), &dst, 7, &[b], &[50]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(route_to(&mac, peer_id), CachedRoute::source(&[b]));

    // A flood-tail copy through B and then C, its last hop marginal.
    mac.clock().advance_ms(50);
    mac.radio_mut().rx_snr = Snr::from_decibels(-10);
    mac.radio_mut().queue_received_traced_unicast(
        &remote,
        &reply_keys(),
        &dst,
        7,
        &[c, b],
        &[0, 50],
    );
    block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(route_to(&mac, peer_id), CachedRoute::source(&[b]));
}

/// A copy that turns up long after the reply it duplicates is a replay, not
/// a path the reply took just now.
#[test]
fn a_stale_duplicate_teaches_nothing() {
    let (mut mac, local_id, _, peer_id) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let (a, b) = (RouterHint([0xA1, 0xA2]), RouterHint([0xB1, 0xB2]));
    mac.radio_mut().rx_snr = Snr::from_decibels(-12);
    mac.radio_mut()
        .queue_received_traced_unicast(&remote, &reply_keys(), &dst, 7, &[a], &[-140]);
    block_on(mac.receive_one(|_, _| {})).unwrap();

    mac.clock().advance_ms(60_000);
    mac.radio_mut().rx_snr = Snr::from_decibels(3);
    mac.radio_mut()
        .queue_received_traced_unicast(&remote, &reply_keys(), &dst, 7, &[b], &[50]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(route_to(&mac, peer_id), CachedRoute::source(&[a]));
}

#[test]
fn a_flood_distance_never_displaces_a_path() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let flood = RouteOffer {
        route: CachedRoute::flood(2, &[]).unwrap(),
        score: None,
        supersedes: false,
        acknowledgment: false,
    };
    let path = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, flood.clone(), 1);
    assert_eq!(
        registry.get(peer_id).unwrap().route,
        Some(flood.route.clone())
    );
    registry.offer_route(peer_id, scored(path.clone(), -400), 2);
    assert_eq!(
        registry.get(peer_id).unwrap().route,
        Some(path.clone()),
        "any path replaces a flood distance"
    );
    registry.offer_route(peer_id, flood, 3);
    assert_eq!(registry.get(peer_id).unwrap().route, Some(path));
}

/// An acknowledgment vouches for the route it answered, so a new path has to
/// beat that route by more than usual, until the acknowledgment ages out.
#[test]
fn an_acknowledged_route_takes_a_larger_margin_to_displace() {
    let (mut mac, _, key, peer_id) = mac_with_keyed_peer();
    let held = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    let better = CachedRoute::source(&[RouterHint([3, 4])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, scored(held.clone(), -200), 1);
    let revision = registry.get(peer_id).unwrap().route_revision;
    registry.confirm_route(&key, revision, 2);

    // 5 dB better: past the switching margin, short of the credit on top.
    registry.offer_route(peer_id, scored(better.clone(), -150), 3);
    assert_eq!(registry.get(peer_id).unwrap().route, Some(held));

    let aged = 3 + crate::route_score::CONFIRMATION_TTL_MS + 1;
    registry.offer_route(peer_id, scored(better.clone(), -150), aged);
    assert_eq!(registry.get(peer_id).unwrap().route, Some(better));
}

/// The first copy of an ack completes the send; a later copy over a better
/// path still teaches that path.
#[test]
fn a_later_copy_of_a_completed_ack_still_teaches_its_route() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let receipt = mac
        .queue_unicast(
            local_id,
            &key,
            b"payload",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next().unwrap();
    let ack = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_trailer;
    let (a, b) = (RouterHint([0xA1, 0xA2]), RouterHint([0xB1, 0xB2]));
    let mut acknowledged = 0;

    mac.radio_mut().rx_snr = Snr::from_decibels(-12);
    mac.radio_mut()
        .queue_received_mac_ack_with_signal(ack, &[a], &[-140]);
    block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::AckReceived { .. }) {
            acknowledged += 1;
        }
    }))
    .unwrap();
    assert_eq!(route_to(&mac, peer_id), CachedRoute::source(&[a]));

    mac.clock().advance_ms(50);
    mac.radio_mut().rx_snr = Snr::from_decibels(3);
    mac.radio_mut()
        .queue_received_mac_ack_with_signal(ack, &[b], &[50]);
    block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::AckReceived { .. }) {
            acknowledged += 1;
        }
    }))
    .unwrap();
    assert_eq!(acknowledged, 1, "only the first copy completes the send");
    assert_eq!(route_to(&mac, peer_id), CachedRoute::source(&[b]));
}

#[test]
fn discovery_sends_and_their_acks_carry_a_trace_signal() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    mac.queue_unicast(
        local_id,
        &key,
        b"payload",
        &SendOptions::default()
            .with_ack_requested(true)
            .with_flood_hops(3),
    )
    .unwrap();
    mac.queue_mac_ack_for_peer(local_id, peer_id, [7; 8], true)
        .unwrap();
    while let Some(queued) = mac.tx_queue_mut().pop_next() {
        let header = PacketHeader::parse(&queued.frame).unwrap();
        let options = ParsedOptions::extract(&queued.frame, header.options_range.clone()).unwrap();
        assert!(options.trace_route.is_some());
        assert!(
            options.trace_signal.is_some(),
            "{:?} traces its route but not what each hop measured",
            header.packet_type()
        );
    }
}

/// Carry `frame` through a repeater with identity `seed` that heard it at
/// `snr`, returning what the repeater forwards and the repeater's hint.
fn forward_through(frame: &[u8], seed: u8, snr: Snr) -> (heapless::Vec<u8, 256>, RouterHint) {
    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    repeater.radio_mut().rx_rssi = -90;
    repeater.radio_mut().rx_snr = snr;
    let id = repeater
        .add_identity(DummyIdentity::new([seed; 32]))
        .unwrap();
    let hint = repeater
        .identity(id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();
    repeater.radio_mut().queue_received_frame(frame);
    block_on(repeater.receive_one(|_, _| {})).unwrap();
    let forwarded = repeater
        .tx_queue_mut()
        .pop_next()
        .expect("the repeater forwards the flood");
    (forwarded.frame.iter().copied().collect(), hint)
}

/// Replies arrive through Z and then, more strongly, through Y. Which one the
/// route should use depends on what this node's own flood showed: whether Z
/// and Y hear us at all.
fn route_after_replies(
    with_uplink_evidence: bool,
) -> (Option<CachedRoute>, RouterHint, RouterHint) {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    mac.queue_unicast(
        local_id,
        &key,
        b"payload",
        &SendOptions::default()
            .with_ack_requested(true)
            .with_flood_hops(3),
    )
    .unwrap();
    block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    let sent = mac.radio().transmitted.last().unwrap().clone();
    // Z takes our flood off the air; Y hears only Z's forward of it.
    let (via_z, z) = forward_through(&sent, 0x20, Snr::from_decibels(3));
    let (via_y, y) = forward_through(&via_z, 0x30, Snr::from_decibels(8));
    if with_uplink_evidence {
        for copy in [&via_z, &via_y] {
            mac.radio_mut().queue_received_frame(copy);
            block_on(mac.receive_one(|_, _| {})).unwrap();
        }
    }

    mac.radio_mut().rx_snr = Snr::from_decibels(3);
    mac.radio_mut()
        .queue_received_traced_unicast(&remote, &reply_keys(), &dst, 7, &[z], &[-40]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    mac.radio_mut()
        .queue_received_traced_unicast(&remote, &reply_keys(), &dst, 8, &[y], &[50]);
    block_on(mac.receive_one(|_, _| {})).unwrap();
    (route_to(&mac, peer_id), z, y)
}

/// Hearing a repeater well says nothing about whether it hears us. A
/// repeater that forwarded our flood only from another repeater's copy is
/// charged as a first hop, so the reply through it, however strong, does not
/// displace the route through one that took our transmission directly.
#[test]
fn a_repeater_that_does_not_hear_us_is_not_chosen_as_the_first_hop() {
    let (route, _, y) = route_after_replies(false);
    assert_eq!(
        route,
        CachedRoute::source(&[y]),
        "without evidence, the stronger reply wins"
    );
    let (route, z, _) = route_after_replies(true);
    assert_eq!(route, CachedRoute::source(&[z]));
}
