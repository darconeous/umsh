use super::*;
use crate::peers::RouteOffer;

/// A route as a received frame would offer it, scored as given.
fn scored(route: CachedRoute, score: i16) -> RouteOffer {
    RouteOffer {
        route,
        score: Some(score),
        supersedes: false,
        acknowledgment: false,
        last_hop: None,
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
                // An empty trace is a direct neighbor, heard here at the
                // dummy radio's strong default: no slack, so no flood field.
                // The restored routes carry no reading, so they earn it.
                let expected = if trace == Some(&[][..]) {
                    None
                } else {
                    Some(match cached.as_ref() {
                        Some(CachedRoute::Source(_)) => 1,
                        Some(CachedRoute::Flood { flood_hops, .. }) if *flood_hops > 0 => {
                            flood_hops + 1
                        }
                        _ => (accumulated + 1).clamp(5, 15),
                    })
                };
                assert_eq!(header.flood_hops.map(|hops| hops.remaining()), expected);
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
        last_hop: None,
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

/// A keyed peer whose route `[1, 2]` is held for `hold_ms`.
fn held_route_mac(hold_ms: u64) -> (TestMac, LocalIdentityId, PublicKey, PeerId, CachedRoute) {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let route = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    let now = mac.clock().now_ms();
    assert!(
        mac.peer_registry_mut()
            .hold_route(peer_id, route.clone(), 1, now + hold_ms, now)
    );
    (mac, local_id, key, peer_id, route)
}

/// Queue one ack-requested send, take it off the queue as if aired, and
/// return its receipt and the ack trailer that will answer it.
fn send_awaiting_ack(
    mac: &mut TestMac,
    local_id: LocalIdentityId,
    key: &PublicKey,
) -> (SendReceipt, [u8; 8]) {
    let receipt = mac
        .queue_unicast(
            local_id,
            key,
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
    (receipt, ack)
}

/// Receive an ack carrying `trace`, returning its `via_route_retry` flag.
fn receive_ack(mac: &mut TestMac, ack: [u8; 8], trace: &[RouterHint]) -> Option<bool> {
    mac.radio_mut()
        .queue_received_mac_ack_with_trace(ack, trace);
    let mut via = None;
    block_on(mac.receive_one(|_, event| {
        if let MacEventRef::AckReceived {
            via_route_retry, ..
        } = event
        {
            via = Some(via_route_retry);
        }
    }))
    .unwrap();
    via
}

#[test]
fn a_held_route_survives_learning_and_keeps_the_best_offer_as_candidate() {
    let (mut mac, _, _, peer_id, route) = held_route_mac(60_000);
    let now = mac.clock().now_ms();
    let weak = CachedRoute::source(&[RouterHint([3, 4])]).unwrap();
    let strong = CachedRoute::source(&[RouterHint([5, 6])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, scored(weak.clone(), -200), now);
    registry.offer_route(
        peer_id,
        RouteOffer {
            supersedes: true,
            ..scored(strong.clone(), -10)
        },
        now,
    );
    // Neither a weaker path nor a flood distance unseats the candidate.
    registry.offer_route(peer_id, scored(weak, -200), now);
    registry.offer_route(
        peer_id,
        RouteOffer {
            route: CachedRoute::flood(2, &[]).unwrap(),
            score: None,
            supersedes: false,
            acknowledgment: false,
            last_hop: None,
        },
        now,
    );
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route, Some(route));
    assert_eq!(
        mac.peer_registry()
            .route_hold(peer_id, now)
            .unwrap()
            .candidate,
        Some(crate::RouteCandidate {
            route: strong,
            score: Some(-10),
            last_hop: None,
        })
    );
}

#[test]
fn a_missed_held_route_floods_but_stays_and_counts_the_fallback() {
    let (mut mac, local_id, key, peer_id, route) = held_route_mac(600_000);

    let (receipt, ack) = send_awaiting_ack(&mut mac, local_id, &key);
    expire_attempt(&mut mac, local_id, receipt);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(route.clone())
    );
    let retry = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(&retry.frame).unwrap();
    assert!(
        ParsedOptions::extract(&retry.frame, header.options_range)
            .unwrap()
            .route_retry
    );

    let learned = [RouterHint([7, 8])];
    assert_eq!(receive_ack(&mut mac, ack, &learned), Some(true));
    let now = mac.clock().now_ms();
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route, Some(route.clone()));
    let hold = mac.peer_registry().route_hold(peer_id, now).unwrap();
    assert_eq!(hold.fallback_acks, 1);
    assert_eq!(
        hold.candidate.as_ref().map(|candidate| &candidate.route),
        CachedRoute::source(&learned).as_ref()
    );

    // The next send goes out on the held route again, and an ack for it
    // resets the count.
    let (_, ack) = send_awaiting_ack(&mut mac, local_id, &key);
    assert_eq!(
        receive_ack(&mut mac, ack, &[RouterHint([1, 2])]),
        Some(false)
    );
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route, Some(route));
    assert_eq!(
        mac.peer_registry()
            .route_hold(peer_id, now)
            .unwrap()
            .fallback_acks,
        0
    );
}

#[test]
fn an_expired_hold_leaves_an_ordinary_route() {
    let (mut mac, _, _, peer_id, route) = held_route_mac(1_000);
    let now = mac.clock().now_ms();
    let measured = CachedRoute::source(&[RouterHint([3, 4])]).unwrap();
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(measured.clone(), -50), now + 999);
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, Some(route));
    assert!(
        mac.peer_registry()
            .route_hold(peer_id, now + 1_000)
            .is_none()
    );
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(measured.clone(), -50), now + 1_000);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(measured)
    );
}

#[test]
fn adopting_or_clearing_ends_the_hold() {
    let (mut mac, _, _, peer_id, route) = held_route_mac(60_000);
    let now = mac.clock().now_ms();
    assert!(!mac.peer_registry_mut().adopt_candidate(peer_id, now));
    let learned = CachedRoute::source(&[RouterHint([3, 4])]).unwrap();
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(learned.clone(), -40), now);
    assert!(mac.peer_registry_mut().adopt_candidate(peer_id, now));
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route, Some(learned));
    assert_eq!(info.route_score(), Some(-40));
    assert!(mac.peer_registry().route_hold(peer_id, now).is_none());

    mac.peer_registry_mut()
        .hold_route(peer_id, route, 1, now + 60_000, now);
    assert!(mac.peer_registry_mut().clear_route(peer_id));
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert!(info.route.is_none());
    assert!(mac.peer_registry().route_hold(peer_id, now).is_none());
}

#[test]
fn holds_are_bounded_and_follow_their_peer() {
    let route = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    let mut registry = PeerRegistry::<4, 1>::new();
    let first = registry.try_insert_or_update(PublicKey([1; 32])).unwrap();
    let second = registry.try_insert_or_update(PublicKey([2; 32])).unwrap();
    let third = registry.try_insert_or_update(PublicKey([3; 32])).unwrap();
    assert!(registry.hold_route(third, route.clone(), 1, 1_000, 0));
    // One slot, taken until the hold runs out.
    assert!(!registry.hold_route(second, route.clone(), 1, 1_000, 0));
    assert!(registry.get(second).unwrap().route.is_none());

    // Removing a peer moves the last one into its slot, hold and all.
    let removal = registry.remove(first).unwrap();
    assert_eq!(removal.moved, Some((third, first)));
    assert!(registry.route_hold(first, 0).is_some());
    assert!(registry.route_hold(second, 0).is_none());

    // A lapsed hold frees its slot.
    assert!(registry.hold_route(second, route.clone(), 1, 2_000, 1_000));
    assert!(registry.route_hold(first, 1_000).is_none());

    // A registry with no room for holds never holds.
    let mut none = PeerRegistry::<4>::new();
    let id = none.try_insert_or_update(PublicKey([1; 32])).unwrap();
    assert!(!none.hold_route(id, route, 1, 1_000, 0));
}

/// The flood budget and source route a queued frame carries.
fn queued_shape(mac: &mut TestMac) -> (Option<u8>, Option<Vec<RouterHint>>) {
    let frame = mac.tx_queue_mut().pop_next().unwrap().frame;
    let header = PacketHeader::parse(&frame).unwrap();
    let options = ParsedOptions::extract(&frame, header.options_range.clone()).unwrap();
    (
        header.flood_hops.map(|hops| hops.remaining()),
        options.source_route.map(|route| {
            frame[route]
                .chunks_exact(2)
                .map(|hint| RouterHint([hint[0], hint[1]]))
                .collect::<std::vec::Vec<_>>()
        }),
    )
}

#[test]
fn a_held_route_floods_its_own_allowance_past_its_end() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let hint = RouterHint([1, 2]);
    let now = mac.clock().now_ms();
    let options = SendOptions::default().with_flood_hops(10);
    assert!(mac.peer_registry_mut().hold_route(
        peer_id,
        CachedRoute::source(&[hint]).unwrap(),
        3,
        now + 60_000,
        now,
    ));
    mac.queue_unicast(local_id, &key, b"routed", &options)
        .unwrap();
    assert_eq!(queued_shape(&mut mac), (Some(3), Some(vec![hint])));

    // A held direct route with no allowance is a single direct transmission.
    assert!(
        mac.peer_registry_mut()
            .hold_route(peer_id, CachedRoute::Direct, 0, now + 60_000, now,)
    );
    mac.queue_unicast(local_id, &key, b"direct", &options)
        .unwrap();
    assert_eq!(queued_shape(&mut mac), (None, None));

    // A send's own allowance wins over the hold's.
    mac.queue_unicast(
        local_id,
        &key,
        b"wider",
        &options.clone().with_route_slack(4),
    )
    .unwrap();
    assert_eq!(queued_shape(&mut mac), (Some(4), None));
}

/// A route offer carrying a measurement of its last hop, the RSSI how
/// whoever first heard the peer heard it.
fn measured(route: CachedRoute, score: i16, last_hop_dbm: i16) -> RouteOffer {
    RouteOffer {
        last_hop: Some(TraceSignalEntry::new(last_hop_dbm, 0)),
        ..scored(route, score)
    }
}

fn last_hop_dbm(mac: &TestMac, peer_id: PeerId) -> Option<i16> {
    mac.peer_registry()
        .get(peer_id)
        .unwrap()
        .route_last_hop()
        .and_then(TraceSignalEntry::rssi_dbm)
}

#[test]
fn a_path_through_the_same_last_repeater_refreshes_the_reading_it_does_not_displace() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let held = CachedRoute::source(&[RouterHint([1, 1]), RouterHint([9, 9])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, measured(held.clone(), -50, -100), 1);
    // Far worse, so it stays a reading and not a route, but the peer is
    // heard by the same repeater.
    let worse = CachedRoute::source(&[RouterHint([2, 2]), RouterHint([9, 9])]).unwrap();
    registry.offer_route(peer_id, measured(worse, -900, -60), 2);
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, Some(held));
    assert_eq!(last_hop_dbm(&mac, peer_id), Some(-60));
}

#[test]
fn a_path_ending_elsewhere_leaves_the_reading_alone() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let held = CachedRoute::source(&[RouterHint([1, 1]), RouterHint([9, 9])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, measured(held, -50, -100), 1);
    let elsewhere = CachedRoute::source(&[RouterHint([1, 1]), RouterHint([8, 8])]).unwrap();
    registry.offer_route(peer_id, measured(elsewhere, -900, -60), 2);
    assert_eq!(last_hop_dbm(&mac, peer_id), Some(-100));
}

#[test]
fn an_offer_that_measured_nothing_keeps_the_last_reading() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let held = CachedRoute::source(&[RouterHint([9, 9])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, measured(held.clone(), -50, -100), 1);
    registry.offer_route(peer_id, scored(held, -50), 2);
    assert_eq!(last_hop_dbm(&mac, peer_id), Some(-100));
}

#[test]
fn a_route_that_takes_over_brings_its_own_reading_or_none() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let registry = mac.peer_registry_mut();
    let first = CachedRoute::source(&[RouterHint([9, 9])]).unwrap();
    registry.offer_route(peer_id, measured(first, -500, -100), 1);
    let better = CachedRoute::source(&[RouterHint([8, 8])]).unwrap();
    registry.offer_route(peer_id, scored(better.clone(), -10), 2);
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route, Some(better));
    assert_eq!(info.route_last_hop(), None);
}

#[test]
fn a_restored_route_has_no_reading_and_was_not_chosen_by_hand() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, measured(CachedRoute::Direct, -10, -60), 1);
    registry.update_route(peer_id, CachedRoute::Direct);
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route_last_hop(), None);
    assert!(!info.route_hand_set);
}

#[test]
fn a_held_route_spends_only_its_allowance_until_a_learned_route_replaces_it() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let now = mac.clock().now_ms();
    let route = CachedRoute::source(&[RouterHint([1, 2])]).unwrap();
    assert!(
        mac.peer_registry_mut()
            .hold_route(peer_id, route, 2, now + 1_000, now)
    );
    // A mobile peer would otherwise earn the slack.
    mac.peer_registry_mut().set_mobile(peer_id, true);
    let send = |mac: &mut TestMac| {
        mac.queue_unicast(local_id, &key, b"payload", &SendOptions::default())
            .unwrap();
        let queued = mac.tx_queue_mut().pop_next().unwrap();
        PacketHeader::parse(&queued.frame)
            .unwrap()
            .flood_hops
            .map(|hops| hops.remaining())
    };
    assert_eq!(send(&mut mac), Some(2));

    // The hold runs out; the route is still the one chosen by hand.
    mac.clock().advance_ms(2_000);
    let now = mac.clock().now_ms();
    assert!(mac.peer_registry().route_hold(peer_id, now).is_none());
    assert_eq!(send(&mut mac), None);

    // A learned route replaces it and earns the slack again.
    let learned = CachedRoute::source(&[RouterHint([7, 7])]).unwrap();
    mac.peer_registry_mut()
        .offer_route(peer_id, scored(learned.clone(), -10), now);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(learned)
    );
    assert_eq!(send(&mut mac), Some(1));
}

#[test]
fn an_ack_along_a_held_route_keeps_the_slack_its_evidence_earns() {
    let (mut mac, local_id, _, peer_id) = mac_with_keyed_peer();
    let now = mac.clock().now_ms();
    mac.peer_registry_mut().set_mobile(peer_id, true);
    let ack = |mac: &mut TestMac, allowance: u8| {
        assert!(mac.peer_registry_mut().hold_route(
            peer_id,
            CachedRoute::Direct,
            allowance,
            now + 60_000,
            now,
        ));
        mac.queue_mac_ack_for_peer(local_id, peer_id, [0; 8], false)
            .unwrap();
        let queued = mac.tx_queue_mut().pop_next().unwrap();
        PacketHeader::parse(&queued.frame)
            .unwrap()
            .flood_hops
            .map(|hops| hops.remaining())
    };
    // The allowance does not narrow the ack below what a mobile peer earns...
    assert_eq!(ack(&mut mac, 0), Some(1));
    // ...and may widen it.
    assert_eq!(ack(&mut mac, 3), Some(3));
}

#[test]
fn an_adopted_candidate_brings_its_reading() {
    let (mut mac, _, _, peer_id, _) = held_route_mac(600_000);
    let now = mac.clock().now_ms();
    let learned = CachedRoute::source(&[RouterHint([7, 7])]).unwrap();
    let registry = mac.peer_registry_mut();
    registry.offer_route(peer_id, measured(learned.clone(), -10, -60), now);
    assert!(registry.adopt_candidate(peer_id, now));
    let info = mac.peer_registry().get(peer_id).unwrap();
    assert_eq!(info.route, Some(learned));
    assert!(!info.route_hand_set);
    assert_eq!(last_hop_dbm(&mac, peer_id), Some(-60));
}

/// Queue one ack-requested send at `flood_hops`, take it off the queue as if
/// aired, and let its ack deadline pass. Returns its receipt and whether the
/// sweep timed it out.
fn send_and_time_out(
    mac: &mut TestMac,
    local_id: LocalIdentityId,
    key: &PublicKey,
    flood_hops: u8,
) -> (SendReceipt, bool) {
    let receipt = mac
        .queue_unicast(
            local_id,
            key,
            b"payload",
            &SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(flood_hops),
        )
        .unwrap()
        .unwrap();
    let sent = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(
        PacketHeader::parse(&sent.frame)
            .unwrap()
            .flood_hops
            .map(|hops| hops.remaining()),
        Some(flood_hops),
        "nothing narrowed the send"
    );
    (receipt, expire_and_report(mac, local_id, receipt))
}

/// As [`expire_attempt`], reporting whether the send timed out.
fn expire_and_report(mac: &mut TestMac, local_id: LocalIdentityId, receipt: SendReceipt) -> bool {
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    let mut timed_out = false;
    mac.service_pending_ack_timeouts(|_, event| {
        if matches!(event, MacEventRef::AckTimeout { .. }) {
            timed_out = true;
        }
    })
    .unwrap();
    timed_out
}

#[test]
fn a_full_budget_flood_retries_once_when_the_peer_was_heard_recently() {
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    mac.clock().advance_ms(1_000);
    let now = mac.clock().now_ms();
    mac.peer_registry_mut().touch(peer_id, now);
    let (receipt, timed_out) = send_and_time_out(&mut mac, local_id, &key, 6);
    assert!(!timed_out);
    let retry = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(&retry.frame).unwrap();
    // The same budget, never a wider one.
    assert_eq!(header.flood_hops.unwrap().remaining(), 6);
    let options = ParsedOptions::extract(&retry.frame, header.options_range).unwrap();
    assert!(options.route_retry);
    assert!(options.trace_route.is_some());
    assert!(options.trace_signal.is_some());
    assert!(options.source_route.is_none());
    // The retry's deadline is armed from when it may air, not left expired.
    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert!(pending.ack_deadline_ms > now);
    // Exactly one per packet: the retry's own timeout ends the send.
    assert!(expire_and_report(&mut mac, local_id, receipt));
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn a_full_budget_flood_to_a_peer_not_heard_recently_just_times_out() {
    // Never heard: a configured peer nothing has arrived from, even right
    // after boot.
    let (mut mac, local_id, key, peer_id) = mac_with_keyed_peer();
    let (_, timed_out) = send_and_time_out(&mut mac, local_id, &key, 6);
    assert!(timed_out);
    assert!(mac.tx_queue().is_empty());

    // Heard, but longer ago than the window.
    let now = mac.clock().now_ms();
    mac.peer_registry_mut().touch(peer_id, now);
    mac.clock()
        .advance_ms(crate::route_score::CONFIRMATION_TTL_MS + 1);
    let (_, timed_out) = send_and_time_out(&mut mac, local_id, &key, 6);
    assert!(timed_out);
    assert!(mac.tx_queue().is_empty());

    // A send that may not flood at all has nothing to retry with.
    let now = mac.clock().now_ms();
    mac.peer_registry_mut().touch(peer_id, now);
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
    assert!(expire_and_report(&mut mac, local_id, receipt));
    assert!(mac.tx_queue().is_empty());
}

const LOST_REPLY_REGION: [u8; 2] = [0x12, 0x34];

/// One copy of an ack-requested unicast from `remote` at counter 7, as it
/// arrived: having flooded `accumulated` hops with `trace` recorded, still
/// to cross `source_route`, and flagged Route Retry when `route_retry`.
/// Every copy carries the same body and MIC; only dynamic fields differ.
fn queue_request_copy(
    mac: &mut TestMac,
    remote: &DummyIdentity,
    accumulated: u8,
    trace: Option<&[RouterHint]>,
    source_route: Option<&[RouterHint]>,
    route_retry: bool,
) {
    let dst = mac
        .identity(LocalIdentityId(0))
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let mut buf = [0u8; 256];
    let mut builder = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_full(remote.public_key())
        .frame_counter(7)
        .encrypted()
        .ack_requested()
        .flood_hops(6);
    if let Some(trace) = trace {
        let (hints, len) = encode_trace(trace);
        builder = builder.option(OptionNumber::TraceRoute, &hints[..len]);
    }
    if let Some(route) = source_route {
        builder = builder.source_route(route);
    }
    if route_retry {
        builder = builder.option(OptionNumber::RouteRetry, &[]);
    }
    let mut packet = builder
        .region_code(LOST_REPLY_REGION)
        .payload(b"payload")
        .build()
        .unwrap();
    packet.as_bytes_mut()[1] = FloodHops::new(6 - accumulated, accumulated).unwrap().0;
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
}

/// Receive one queued frame, returning how many payloads it delivered.
fn receive_counting(mac: &mut TestMac) -> usize {
    let mut delivered = 0;
    block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::UnicastAckReq) {
            delivered += 1;
        }
    }))
    .unwrap();
    delivered
}

/// The shape of the next queued MAC ack: `FHOPS_REM`, source route, whether
/// it traces (with its signal), and its region codes.
#[derive(Debug, PartialEq, Eq)]
struct AckShape {
    flood_hops: Option<u8>,
    source_route: Option<Vec<RouterHint>>,
    traced: bool,
    regions: Vec<[u8; 2]>,
}

fn queued_ack_shape(mac: &mut TestMac) -> AckShape {
    let frame = mac.tx_queue_mut().pop_next().unwrap().frame;
    let header = PacketHeader::parse(&frame).unwrap();
    assert_eq!(header.packet_type(), PacketType::MacAck);
    let options = ParsedOptions::extract(&frame, header.options_range.clone()).unwrap();
    assert_eq!(
        options.trace_route.is_some(),
        options.trace_signal.is_some()
    );
    let regions = umsh_core::iter_options(&frame, header.options_range.clone())
        .map(Result::unwrap)
        .filter(|(number, _)| *number == OptionNumber::RegionCode.as_u16())
        .map(|(_, value)| [value[0], value[1]])
        .collect();
    AckShape {
        flood_hops: header.flood_hops.map(|hops| hops.remaining()),
        source_route: options.source_route.map(|route| {
            frame[route]
                .chunks_exact(2)
                .map(|hint| RouterHint([hint[0], hint[1]]))
                .collect()
        }),
        traced: options.trace_route.is_some(),
        regions,
    }
}

/// Past the duplicate-ack holdoff, and then some.
const LATE_MS: u64 = 60_000;

#[test]
fn a_route_retry_of_an_acked_request_reacks_by_scoped_flood_and_retires_the_route() {
    let dead = [RouterHint([4, 5])];
    let fresh = [RouterHint([6, 7])];
    // The retry may trace the dead route's own path (a link that works only
    // toward us) or a different one.
    for retry_trace in [dead, fresh] {
        let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
        let remote = DummyIdentity::new([0xAB; 32]);
        mac.peer_registry_mut()
            .update_route(peer_id, CachedRoute::source(&dead).unwrap());

        // The original floods in untraced: a flood distance never displaces
        // the path held, so the ack goes down the dead route.
        queue_request_copy(&mut mac, &remote, 2, None, None, false);
        assert_eq!(receive_counting(&mut mac), 1);
        assert_eq!(queued_ack_shape(&mut mac).source_route, Some(dead.to_vec()));

        mac.clock().advance_ms(LATE_MS);
        queue_request_copy(&mut mac, &remote, 3, Some(&retry_trace), None, true);
        assert_eq!(
            receive_counting(&mut mac),
            0,
            "a duplicate is not delivered"
        );
        // The re-ack reaches as far as the retry came, plus a hop, within
        // its regions, and traces so the sender learns a way back.
        assert_eq!(
            queued_ack_shape(&mut mac),
            AckShape {
                flood_hops: Some(4),
                source_route: None,
                traced: true,
                regions: vec![LOST_REPLY_REGION],
            }
        );
        assert!(mac.tx_queue().is_empty());
        // The dead route is retired and not taught straight back; a
        // different path the retry traced is an ordinary candidate.
        let expected = (retry_trace != dead).then(|| CachedRoute::source(&fresh).unwrap());
        assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, expected);
    }
}

#[test]
fn a_late_plain_retransmission_of_an_acked_request_reacks_along_the_route() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let route = [RouterHint([4, 5])];
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::source(&route).unwrap());
    queue_request_copy(&mut mac, &remote, 2, None, None, false);
    receive_counting(&mut mac);
    mac.tx_queue_mut().pop_next().unwrap();

    // Without Route Retry the copy may have crossed our ack on its way, so
    // it proves nothing about the route.
    mac.clock().advance_ms(LATE_MS);
    queue_request_copy(&mut mac, &remote, 2, None, None, false);
    receive_counting(&mut mac);
    assert_eq!(
        queued_ack_shape(&mut mac).source_route,
        Some(route.to_vec())
    );
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        CachedRoute::source(&route)
    );
}

#[test]
fn a_route_retry_of_a_request_never_acked_gets_its_first_ack() {
    let (mut mac, _, _, peer_id) = mac_with_keyed_peer();
    let remote = DummyIdentity::new([0xAB; 32]);
    let route = [RouterHint([6, 7])];
    // Overheard before the last repeater consumed its hint: accepted, and
    // teaching the route, but not ours to acknowledge yet.
    queue_request_copy(&mut mac, &remote, 0, Some(&[]), Some(&route), false);
    assert_eq!(receive_counting(&mut mac), 1);
    assert!(mac.tx_queue().is_empty());
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        CachedRoute::source(&route)
    );

    mac.clock().advance_ms(LATE_MS);
    queue_request_copy(&mut mac, &remote, 0, Some(&route), Some(&[]), true);
    assert_eq!(receive_counting(&mut mac), 0);
    // Nothing was lost: the route stands and the ack follows it.
    assert_eq!(
        queued_ack_shape(&mut mac).source_route,
        Some(route.to_vec())
    );
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        CachedRoute::source(&route)
    );
}

#[test]
fn a_lost_reply_floods_the_reack_but_leaves_a_held_route_held() {
    let (mut mac, _, _, peer_id, held) = held_route_mac(600_000);
    let remote = DummyIdentity::new([0xAB; 32]);
    queue_request_copy(&mut mac, &remote, 2, None, None, false);
    receive_counting(&mut mac);
    assert_eq!(
        queued_ack_shape(&mut mac).source_route,
        Some(vec![RouterHint([1, 2])])
    );

    mac.clock().advance_ms(LATE_MS);
    let fresh = [RouterHint([6, 7])];
    queue_request_copy(&mut mac, &remote, 3, Some(&fresh), None, true);
    receive_counting(&mut mac);
    let shape = queued_ack_shape(&mut mac);
    assert_eq!(shape.source_route, None);
    assert_eq!(shape.flood_hops, Some(4));
    assert!(shape.traced);
    let now = mac.clock().now_ms();
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, Some(held));
    assert_eq!(
        mac.peer_registry()
            .route_hold(peer_id, now)
            .and_then(|hold| hold.candidate.as_ref())
            .map(|candidate| candidate.route.clone()),
        CachedRoute::source(&fresh)
    );
}
