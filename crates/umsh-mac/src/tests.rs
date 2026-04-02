use super::*;
use core::{cell::{Cell, RefCell}, future::Future, pin::pin, task::{Context, Poll, RawWaker, RawWakerVTable, Waker}};
use hamaddr::HamAddr;
use umsh_core::{iter_options, ChannelId, ChannelKey, FloodHops, OptionNumber, PacketBuilder, PacketHeader, PacketType, PublicKey, RouterHint};
use umsh_crypto::{AesCipher, AesProvider, CryptoEngine, DerivedChannelKeys, NodeIdentity, PairwiseKeys, Sha256Provider, SharedSecret};
use umsh_hal::{Clock, CounterStore, Radio, Rng, RxInfo};

#[test]
fn duplicate_cache_evicts_oldest_entry() {
    let mut cache = DuplicateCache::<2>::new();
    cache.insert(DupCacheKey::Hash32(1), 1);
    cache.insert(DupCacheKey::Hash32(2), 2);
    cache.insert(DupCacheKey::Hash32(3), 3);

    assert!(!cache.contains(&DupCacheKey::Hash32(1)));
    assert!(cache.contains(&DupCacheKey::Hash32(2)));
    assert!(cache.contains(&DupCacheKey::Hash32(3)));
}

#[test]
fn replay_window_detects_replay_and_window_expiry() {
    let mut window = ReplayWindow::new();
    let mic = [0x11u8; 8];

    assert_eq!(window.check(10, &mic, 1), ReplayVerdict::Accept);
    window.accept(10, &mic, 1);
    assert_eq!(window.check(10, &mic, 2), ReplayVerdict::Replay);
    assert_eq!(window.check(1, &mic, 2), ReplayVerdict::OutOfWindow);
    assert_eq!(window.check(10, &mic, crate::REPLAY_STALE_MS + 2), ReplayVerdict::Stale);
}

#[test]
fn replay_window_accepts_forward_jump_of_eight_without_panicking() {
    let mut window = ReplayWindow::new();
    let mic = [0x22u8; 8];

    window.accept(10, &mic, 1);
    window.accept(18, &mic, 2);

    assert_eq!(window.backward_bitmap, 1 << 7);
}

#[test]
fn peer_registry_looks_up_by_hint_and_updates_route() {
    let mut registry = PeerRegistry::<4>::new();
    let key = PublicKey([0xA1; 32]);
    let peer_id = registry.insert_or_update(key);

    let matches: heapless::Vec<PeerId, 4> = registry.lookup_by_hint(&key.hint()).map(|(id, _)| id).collect();
    assert_eq!(matches.as_slice(), &[peer_id]);

    let mut route = heapless::Vec::new();
    route.push(RouterHint([1, 2])).unwrap();
    registry.update_route(peer_id, CachedRoute::Source(route.clone()));
    assert_eq!(registry.get(peer_id).unwrap().route, Some(CachedRoute::Source(route)));
}

#[test]
fn channel_table_updates_existing_channel() {
    let mut table = ChannelTable::<2>::new();
    let key_a = ChannelKey([0x11; 32]);
    let key_b = ChannelKey([0x22; 32]);
    let derived_a = umsh_crypto::DerivedChannelKeys { k_enc: [1; 16], k_mic: [2; 16], channel_id: ChannelId([0xAA, 0xBB]) };
    let derived_b = umsh_crypto::DerivedChannelKeys { k_enc: [3; 16], k_mic: [4; 16], channel_id: ChannelId([0xAA, 0xBB]) };

    table.add(key_a, derived_a);
    table.add(key_b.clone(), derived_b.clone());

    let stored = table.lookup_by_id(&derived_b.channel_id).next().unwrap();
    assert_eq!(stored.channel_key.0, key_b.0);
    assert_eq!(stored.derived.k_enc, derived_b.k_enc);
}

#[test]
fn send_options_default_to_encrypted_flooded_mic16() {
    let options = SendOptions::default();
    assert_eq!(options.mic_size, umsh_core::MicSize::Mic16);
    assert!(options.encrypted);
    assert!(!options.ack_requested);
    assert_eq!(options.flood_hops, Some(5));
    assert!(options.source_route.is_none());
}

#[test]
fn send_options_copy_source_route_and_reject_oversize_routes() {
    let route = [RouterHint([1, 2]), RouterHint([3, 4])];
    let options = SendOptions::default().try_with_source_route(&route).unwrap();
    assert_eq!(options.source_route.unwrap().as_slice(), &route);

    let too_long = [RouterHint([9, 9]); crate::MAX_SOURCE_ROUTE_HOPS + 1];
    assert_eq!(SendOptions::default().try_with_source_route(&too_long), Err(CapacityError));
}

#[test]
fn direct_ack_requested_starts_awaiting_ack() {
    let resend: ResendRecord = ResendRecord::try_new(b"hello", None).unwrap();
    let pending = PendingAck::direct([0xAA; 8], PublicKey([0x11; 32]), resend, 10, 100);
    assert_eq!(pending.state, AckState::AwaitingAck);
}

#[test]
fn forwarded_ack_requested_starts_awaiting_forward() {
    let resend: ResendRecord = ResendRecord::try_new(b"hello", Some(&[RouterHint([1, 2])])).unwrap();
    let pending = PendingAck::forwarded([0xBB; 8], PublicKey([0x22; 32]), resend, 10, 100, 25);
    assert_eq!(pending.state, AckState::AwaitingForward { confirm_deadline_ms: 25 });
}

#[test]
fn tx_queue_pops_highest_priority_first_then_fifo_within_priority() {
    let mut queue = TxQueue::<8>::new();
    queue.enqueue(TxPriority::Application, b"app-a", None).unwrap();
    queue.enqueue(TxPriority::Retry, b"retry", Some(SendReceipt(1))).unwrap();
    queue.enqueue(TxPriority::ImmediateAck, b"ack", None).unwrap();
    queue.enqueue(TxPriority::Application, b"app-b", None).unwrap();

    assert_eq!(queue.pop_next().unwrap().frame.as_slice(), b"ack");
    assert_eq!(queue.pop_next().unwrap().frame.as_slice(), b"retry");
    assert_eq!(queue.pop_next().unwrap().frame.as_slice(), b"app-a");
    assert_eq!(queue.pop_next().unwrap().frame.as_slice(), b"app-b");
    assert!(queue.is_empty());
}

#[test]
fn identity_slot_rejects_pending_ack_when_table_is_full() {
    let identity = LocalIdentity::LongTerm(DummyIdentity::new([0x44; 32]));
    let mut slot = IdentitySlot::<DummyIdentity, 4, 1>::new(identity, 0, None);
    let resend: ResendRecord = ResendRecord::try_new(b"hello", None).unwrap();

    let receipt = slot.next_receipt();
    slot.try_insert_pending_ack(receipt, PendingAck::direct([0xAA; 8], PublicKey([1; 32]), resend.clone(), 1, 2)).unwrap();
    let second_receipt = slot.next_receipt();

    assert_eq!(
        slot.try_insert_pending_ack(second_receipt, PendingAck::direct([0xBB; 8], PublicKey([2; 32]), resend, 1, 2)),
        Err(PendingAckError::TableFull)
    );
}

#[test]
fn mac_adds_identities_peers_and_channels() {
    let mut mac = make_mac();

    let id_a = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let id_b = mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();
    let peer = mac.add_peer(PublicKey([0xAB; 32]));
    mac.add_channel(ChannelKey([0x5A; 32])).unwrap();

    assert_eq!(id_a, LocalIdentityId(0));
    assert_eq!(id_b, LocalIdentityId(1));
    assert_eq!(mac.identity_count(), 2);
    assert_eq!(mac.identity(id_b).unwrap().identity().hint(), umsh_core::NodeHint([0x20; 3]));
    assert_eq!(mac.peer_registry().get(peer).unwrap().public_key, PublicKey([0xAB; 32]));
    assert_eq!(mac.channels().len(), 1);
}

#[test]
fn queue_unicast_requires_installed_pairwise_keys() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let _peer_id = mac.add_peer(peer_key);

    assert_eq!(mac.queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default()), Err(SendError::PairwiseKeysMissing));
}

#[test]
fn queue_unicast_enqueues_frame_and_pending_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac.queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood()).unwrap().unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_some());
}

#[test]
fn mac_handle_clones_share_send_queue_state() {
    let mac = RefCell::new(make_mac());
    let handle = MacHandle::new(&mac);
    let handle_clone = handle.clone();

    let local_id = handle.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = handle_clone.add_peer(peer_key).unwrap();
    handle
        .install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] })
        .unwrap();

    let receipt = handle_clone
        .send_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();

    let borrowed = mac.borrow();
    assert_eq!(borrowed.tx_queue().len(), 1);
    assert!(borrowed.identity(local_id).unwrap().pending_ack(&receipt).is_some());
}

#[test]
fn queue_blind_unicast_requires_known_channel() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    assert_eq!(
        mac.queue_blind_unicast(local_id, &peer_key, &ChannelId([0xAA, 0xBB]), b"hello", &SendOptions::default()),
        Err(SendError::ChannelMissing)
    );
}

#[test]
fn licensed_only_mode_rejects_encrypted_unicast() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign = Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    assert_eq!(
        mac.queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().no_flood()),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn licensed_only_mode_rejects_encrypted_blind_unicast() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign = Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();
    mac.add_channel(channel_key).unwrap();

    assert_eq!(
        mac.queue_blind_unicast(local_id, &peer_key, &channel_id, b"hello", &SendOptions::default()),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn licensed_only_mode_allows_unencrypted_blind_unicast_with_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign = Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();
    mac.add_channel(channel_key).unwrap();

    assert!(mac
        .queue_blind_unicast(local_id, &peer_key, &channel_id, b"hello", &SendOptions::default().unencrypted())
        .is_ok());
}

#[test]
fn hybrid_mode_allows_encrypted_unicast_without_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::Hybrid;

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    assert!(mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().no_flood())
        .is_ok());
}

#[test]
fn unlicensed_mode_allows_blind_unicast_without_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::Unlicensed;

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();
    mac.add_channel(channel_key).unwrap();

    assert!(mac
        .queue_blind_unicast(local_id, &peer_key, &channel_id, b"hello", &SendOptions::default())
        .is_ok());
}

#[test]
fn queue_broadcast_injects_operator_callsign_option() {
    let mut mac = make_mac();
    mac.operating_policy_mut().operator_callsign = Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.queue_broadcast(local_id, b"hello", &SendOptions::default().unencrypted().no_flood())
        .unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    let operator = iter_options(queued.frame.as_slice(), header.options_range)
        .find_map(|entry| match entry.unwrap() {
            (number, value) if OptionNumber::from(number) == OptionNumber::OperatorCallsign => Some(value.to_vec()),
            _ => None,
        })
        .unwrap();

    assert_eq!(operator, HamAddr::try_from_callsign("KZ2X").unwrap().as_trimmed_slice());
}

#[test]
fn receive_one_delivers_broadcast_to_all_identities() {
    let mut mac = make_mac();
    let id_a = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let id_b = mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);

    mac.radio_mut().queue_received_broadcast(&remote, &[1, 0x44, 0x55]);

    let mut seen = heapless::Vec::<(LocalIdentityId, PublicKey, heapless::Vec<u8, 8>), 4>::new();
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::Broadcast { from_hint: _, from_key, payload } = event {
            let mut body = heapless::Vec::new();
            for byte in payload {
                body.push(*byte).unwrap();
            }
            seen.push((identity, from_key.unwrap(), body)).unwrap();
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, id_a);
    assert_eq!(seen[1].0, id_b);
    assert_eq!(seen[0].1, *remote.public_key());
    assert_eq!(seen[0].2.as_slice(), &[1, 0x44, 0x55]);
}

#[test]
fn receive_one_drops_broadcast_with_incompatible_payload_type() {
    let mut mac = make_mac();
    let _id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);

    mac.radio_mut().queue_received_broadcast(&remote, &[3, b'h', b'i']);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if let MacEventRef::Broadcast { .. } = event {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
}

#[test]
fn receive_one_drops_multicast_with_incompatible_payload_type() {
    let mut mac = make_mac();
    let _id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key).unwrap();
    let derived = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };

    mac.radio_mut().queue_received_multicast(&remote, channel_id, &derived, &[5, 0x01]);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if let MacEventRef::Multicast { .. } = event {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
}

#[test]
fn channel_policy_requires_full_source_for_multicast() {
    let mut mac = make_mac();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.operating_policy_mut()
        .channel_policies
        .push(ChannelPolicy {
            channel_id,
            require_unencrypted: false,
            require_full_source: true,
            max_flood_hops: None,
        })
        .unwrap();

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.add_channel(channel_key).unwrap();

    assert_eq!(
        mac.queue_multicast(local_id, &channel_id, b"hello", &SendOptions::default().unencrypted()),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn channel_policy_requires_unencrypted_multicast() {
    let mut mac = make_mac();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.operating_policy_mut()
        .channel_policies
        .push(ChannelPolicy {
            channel_id,
            require_unencrypted: true,
            require_full_source: false,
            max_flood_hops: None,
        })
        .unwrap();

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.add_channel(channel_key).unwrap();

    assert_eq!(
        mac.queue_multicast(local_id, &channel_id, b"hello", &SendOptions::default()),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn channel_policy_rejects_excess_flood_hops() {
    let mut mac = make_mac();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.operating_policy_mut()
        .channel_policies
        .push(ChannelPolicy {
            channel_id,
            require_unencrypted: false,
            require_full_source: false,
            max_flood_hops: Some(1),
        })
        .unwrap();

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.add_channel(channel_key).unwrap();

    assert_eq!(
        mac.queue_multicast(local_id, &channel_id, b"hello", &SendOptions::default().with_flood_hops(2).unencrypted()),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn queue_blind_unicast_enqueues_frame_and_pending_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();
    mac.add_channel(channel_key).unwrap();

    let receipt = mac
        .queue_blind_unicast(local_id, &peer_key, &channel_id, b"hello", &SendOptions::default().with_ack_requested(true))
        .unwrap()
        .unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::BlindUnicastAckReq);
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_some());
}

#[test]
fn queue_multicast_enqueues_frame_for_known_channel() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key).unwrap();

    mac.queue_multicast(local_id, &channel_id, b"hello", &SendOptions::default()).unwrap();
    assert_eq!(mac.tx_queue().len(), 1);
}

#[test]
fn drain_tx_queue_transmits_all_queued_frames_in_priority_order() {
    let mut mac = make_mac();
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"app", None).unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::Retry, b"retry", Some(SendReceipt(7))).unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::ImmediateAck, b"ack", None).unwrap();

    block_on(mac.drain_tx_queue()).unwrap();

    assert!(mac.tx_queue().is_empty());
    let sent = &mac.radio().transmitted;
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0].as_slice(), b"ack");
    assert_eq!(sent[1].as_slice(), b"retry");
    assert_eq!(sent[2].as_slice(), b"app");
    assert_eq!(mac.radio().cad_calls, 2);
}

#[test]
fn transmit_next_requeues_non_immediate_frame_when_cad_detects_activity() {
    let mut mac = make_mac();
    mac.radio_mut().cad_responses.push_back(true).unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"app", Some(SendReceipt(3))).unwrap();

    let receipt = block_on(mac.transmit_next()).unwrap();

    assert_eq!(receipt, None);
    assert!(mac.radio().transmitted.is_empty());
    assert_eq!(mac.radio().cad_calls, 1);
    assert_eq!(mac.tx_queue().len(), 1);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::Application);
    assert_eq!(queued.receipt, Some(SendReceipt(3)));
    assert_eq!(queued.frame.as_slice(), b"app");
    assert_eq!(queued.cad_attempts, 1);
    assert!(queued.not_before_ms >= mac.clock().now_ms());
}

#[test]
fn transmit_next_waits_for_backoff_deadline_before_retrying_cad() {
    let mut mac = make_mac();
    mac.radio_mut().cad_responses.push_back(true).unwrap();
    mac.radio_mut().cad_responses.push_back(false).unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"app", Some(SendReceipt(3))).unwrap();

    assert_eq!(block_on(mac.transmit_next()).unwrap(), None);
    assert_eq!(mac.radio().cad_calls, 1);

    assert_eq!(block_on(mac.transmit_next()).unwrap(), None);
    assert_eq!(mac.radio().cad_calls, 1);
    assert!(mac.radio().transmitted.is_empty());

    mac.clock().advance_ms(1_000);
    assert_eq!(block_on(mac.transmit_next()).unwrap(), Some(SendReceipt(3)));
    assert_eq!(mac.radio().cad_calls, 2);
    assert_eq!(mac.radio().transmitted.len(), 1);
}

#[test]
fn transmit_next_drops_frame_after_five_busy_cad_attempts() {
    let mut mac = make_mac();
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
    }
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"app", Some(SendReceipt(3))).unwrap();

    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        let _ = block_on(mac.transmit_next()).unwrap();
        mac.clock().advance_ms(1_000);
    }

    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.radio().cad_calls, crate::MAX_CAD_ATTEMPTS as u32);
    assert!(mac.radio().transmitted.is_empty());
}

#[test]
fn transmit_next_immediate_ack_skips_cad() {
    let mut mac = make_mac();
    mac.radio_mut().cad_responses.push_back(true).unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::ImmediateAck, b"ack", None).unwrap();

    let receipt = block_on(mac.transmit_next()).unwrap();

    assert_eq!(receipt, None);
    assert_eq!(mac.radio().cad_calls, 0);
    assert_eq!(mac.radio().transmitted.len(), 1);
    assert_eq!(mac.radio().transmitted[0].as_slice(), b"ack");
}

#[test]
fn queue_mac_ack_builds_immediate_ack_frame() {
    let mut mac = make_mac();
    let dst = RouterHint([0x12, 0x34]);
    let ack_tag = [0xA5; 8];

    mac.queue_mac_ack(dst, ack_tag).unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.ack_dst, Some(dst.0));
    assert_eq!(&queued.frame.as_slice()[header.mic_range], &ack_tag);
}

#[test]
fn queued_mac_ack_transmits_before_application_traffic() {
    let mut mac = make_mac();
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"app", None).unwrap();
    mac.queue_mac_ack(RouterHint([0x55, 0x66]), [0xCC; 8]).unwrap();

    block_on(mac.drain_tx_queue()).unwrap();

    assert_eq!(mac.radio().transmitted.len(), 2);
    let ack_header = PacketHeader::parse(mac.radio().transmitted[0].as_slice()).unwrap();
    assert_eq!(ack_header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(mac.radio().transmitted[1].as_slice(), b"app");
}

#[test]
fn receive_one_emits_ack_received_for_matching_mac_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    let ack_tag = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().ack_tag;
    let ack_dst = mac.identity(local_id).unwrap().identity().public_key().router_hint();
    mac.radio_mut().queue_received_mac_ack(ack_dst, ack_tag);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::AckReceived { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

#[test]
fn receive_one_ignores_unmatched_mac_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    let ack_dst = mac.identity(local_id).unwrap().identity().public_key().router_hint();
    mac.radio_mut().queue_received_mac_ack(ack_dst, [0xEE; 8]);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::AckReceived { .. }) {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_some());
}

#[test]
fn receive_one_emits_ack_received_for_matching_blind_unicast_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();
    mac.add_channel(channel_key).unwrap();

    let receipt = mac
        .queue_blind_unicast(local_id, &peer_key, &channel_id, b"hello", &SendOptions::default().with_ack_requested(true))
        .unwrap()
        .unwrap();
    let ack_tag = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().ack_tag;
    let ack_dst = mac.identity(local_id).unwrap().identity().public_key().router_hint();
    mac.radio_mut().queue_received_mac_ack(ack_dst, ack_tag);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::AckReceived { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

#[test]
fn receive_one_delivers_unicast_and_queues_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut().queue_received_unicast(&remote, &keys, &dst_hint, b"hello", true);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::Unicast { from, payload, ack_requested } = event {
            seen = Some((identity, from, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, b"hello".to_vec(), true)));
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.ack_dst, Some(peer_key.router_hint().0));
}

#[test]
fn receive_one_delivers_unicast_without_ack_when_not_requested() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut().queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if let MacEventRef::Unicast { ack_requested, .. } = event {
            seen = !ack_requested;
        }
    }))
    .unwrap();

    assert!(handled);
    assert!(seen);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_drops_replayed_unicast_after_first_delivery() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut().queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);
    mac.radio_mut().queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let mut deliveries = 0;
    assert!(block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::Unicast { .. }) {
            deliveries += 1;
        }
    }))
    .unwrap());

    assert!(!block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::Unicast { .. }) {
            deliveries += 1;
        }
    }))
    .unwrap());

    assert_eq!(deliveries, 1);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_unicast_with_ambiguous_hint_tries_candidate_peers() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let candidate_a = PublicKey([
        0xAB, 0xAB, 0xAB, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let candidate_b = PublicKey([
        0xAB, 0xAB, 0xAB, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let _peer_a = mac.add_peer(candidate_a);
    let peer_b = mac.add_peer(candidate_b);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_b, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut().queue_received_unicast_with_source_hint(candidate_b.hint(), &keys, &dst_hint, b"hello", false);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::Unicast { from, payload, ack_requested } = event {
            seen = Some((identity, from, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, candidate_b, b"hello".to_vec(), false)));
}

#[test]
fn receive_one_delivers_blind_unicast_and_queues_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let pairwise = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone()).unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut()
        .queue_received_blind_unicast(&remote, &pairwise, &channel_keys, &dst_hint, b"hello", true);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::BlindUnicast { from, channel_id, payload, ack_requested } = event {
            seen = Some((identity, from, channel_id, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, channel_id, b"hello".to_vec(), true)));
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.ack_dst, Some(peer_key.router_hint().0));
}

#[test]
fn receive_one_delivers_unencrypted_blind_unicast() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let pairwise = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone()).unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut().queue_received_unencrypted_blind_unicast(&remote, &pairwise, &channel_keys, &dst_hint, b"hello", false);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::BlindUnicast { from, channel_id, payload, ack_requested } = event {
            seen = Some((identity, from, channel_id, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, channel_id, b"hello".to_vec(), false)));
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_delivers_source_routed_unicast_without_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();
    let route = [RouterHint([0x44, 0x55])];

    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        true,
        None,
        None,
        Some(&route),
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::Unicast { from, payload, ack_requested } = event {
            seen = Some((identity, from, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, b"hello".to_vec(), true)));
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_delivers_source_routed_blind_unicast_without_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let pairwise = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone()).unwrap();

    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();
    let channel_keys = mac.channels().lookup_by_id(&channel_id).next().unwrap().derived.clone();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();
    let route = [RouterHint([0x44, 0x55])];

    mac.radio_mut().queue_received_blind_unicast_with_route(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        true,
        Some(&route),
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::BlindUnicast {
            from,
            channel_id,
            payload,
            ack_requested,
        } = event
        {
            seen = Some((identity, from, channel_id, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, channel_id, b"hello".to_vec(), true)));
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_drops_replayed_blind_unicast_after_first_delivery() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let pairwise = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone()).unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut()
        .queue_received_blind_unicast(&remote, &pairwise, &channel_keys, &dst_hint, b"hello", false);
    mac.radio_mut()
        .queue_received_blind_unicast(&remote, &pairwise, &channel_keys, &dst_hint, b"hello", false);

    let mut deliveries = 0;
    assert!(block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::BlindUnicast { .. }) {
            deliveries += 1;
        }
    }))
    .unwrap());

    assert!(!block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::BlindUnicast { .. }) {
            deliveries += 1;
        }
    }))
    .unwrap());

    assert_eq!(deliveries, 1);
}

#[test]
fn receive_one_blind_unicast_with_ambiguous_hint_tries_candidate_peers() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let candidate_a = PublicKey([
        0xAB, 0xAB, 0xAB, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let candidate_b = PublicKey([
        0xAB, 0xAB, 0xAB, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let _peer_a = mac.add_peer(candidate_a);
    let peer_b = mac.add_peer(candidate_b);
    let pairwise = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    let channel_id = channel_keys.channel_id;
    mac.install_pairwise_keys(local_id, peer_b, pairwise.clone()).unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.radio_mut()
        .queue_received_blind_unicast_with_source_hint(candidate_b.hint(), &pairwise, &channel_keys, &dst_hint, b"hello", false);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::BlindUnicast { from, channel_id, payload, ack_requested } = event {
            seen = Some((identity, from, channel_id, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, candidate_b, channel_id, b"hello".to_vec(), false)));
}

#[test]
fn receive_one_repeater_forwards_blind_unicast_using_original_encrypted_frame() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac.identity(repeater_id).unwrap().identity().public_key().router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let pairwise = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();
    let channel_keys = mac.channels().lookup_by_id(&channel_id).next().unwrap().derived.clone();
    let dst_hint = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    let source_route = [repeater_hint, RouterHint([0x21, 0x22])];
    let original = build_received_blind_unicast_frame(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        false,
        Some(&source_route),
    );

    mac.radio_mut().queue_received_frame(original.as_slice());

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let original_header = PacketHeader::parse(original.as_slice()).unwrap();
    let forwarded_header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    assert_eq!(
        &forwarded.frame.as_slice()[forwarded_header.body_range.start - 8..forwarded_header.body_range.start],
        &original.as_slice()[original_header.body_range.start - 8..original_header.body_range.start],
    );
}

#[test]
fn receive_one_delivers_multicast_for_known_channel() {
    let mut mac = make_mac();
    let first_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let second_id = mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_peer(peer_key);
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys { k_enc: derived.k_enc, k_mic: derived.k_mic };
    mac.radio_mut().queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut seen = heapless::Vec::<(LocalIdentityId, PublicKey, ChannelId, std::vec::Vec<u8>), 4>::new();
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::Multicast { from, channel_id, payload } = event {
            seen.push((identity, from, channel_id, payload.to_vec())).unwrap();
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen.as_slice(),
        &[
            (first_id, peer_key, channel_id, b"group".to_vec()),
            (second_id, peer_key, channel_id, b"group".to_vec()),
        ]
    );
}

#[test]
fn receive_one_drops_replayed_multicast_after_first_delivery() {
    let mut mac = make_mac();
    let _local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_peer(peer_key);
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys { k_enc: derived.k_enc, k_mic: derived.k_mic };
    mac.radio_mut().queue_received_multicast(&remote, channel_id, &keys, b"group");
    mac.radio_mut().queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut deliveries = 0;
    assert!(block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::Multicast { .. }) {
            deliveries += 1;
        }
    }))
    .unwrap());

    assert!(!block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::Multicast { .. }) {
            deliveries += 1;
        }
    }))
    .unwrap());

    assert_eq!(deliveries, 1);
}

#[test]
fn receive_one_ignores_multicast_for_unknown_channel() {
    let mut mac = make_mac();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys { k_enc: derived.k_enc, k_mic: derived.k_mic };
    mac.add_peer(peer_key);
    mac.radio_mut().queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if matches!(event, MacEventRef::Multicast { .. }) {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
}

#[test]
fn receive_one_multicast_with_full_registry_drops_unknown_sender_without_panicking() {
    let mut mac = make_small_peer_mac::<1>();
    let _local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let known_peer = PublicKey([0xCD; 32]);
    let _peer_id = mac.add_peer(known_peer);
    let remote = DummyIdentity::new([0xAB; 32]);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys { k_enc: derived.k_enc, k_mic: derived.k_mic };
    mac.radio_mut().queue_received_multicast(&remote, channel_id, &keys, b"group");

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(!handled);
    assert_eq!(mac.peer_registry().get(PeerId(0)).unwrap().public_key, known_peer);
}

#[test]
fn receive_one_learns_reversed_trace_route_for_unicast_sender() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();
    let trace = [RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])];

    mac.radio_mut()
        .queue_received_unicast_with_route(&remote, &keys, &dst_hint, b"hello", false, None, Some(&trace), None);

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Source(heapless::Vec::from_slice(&[RouterHint([0x03, 0x04]), RouterHint([0x01, 0x02])]).unwrap()))
    );
}

#[test]
fn receive_one_learns_flood_hops_for_multicast_sender() {
    let mut mac = make_mac();
    let _local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys { k_enc: derived.k_enc, k_mic: derived.k_mic };
    mac.radio_mut()
        .queue_received_multicast_with_flood(&remote, channel_id, &keys, b"group", Some((4, 2)));

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Flood { hops: 2 })
    );
}

#[test]
fn receive_one_confirms_forwarded_send_when_same_frame_is_overheard() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let route = [RouterHint([1, 2])];
    let options = SendOptions::default().with_ack_requested(true).try_with_source_route(&route).unwrap();
    let receipt = mac.queue_unicast(local_id, &peer_key, b"hello", &options).unwrap().unwrap();
    let _ = block_on(mac.transmit_next()).unwrap();
    let original_frame = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().resend.frame.clone();
    let forwarded_frame = rewrite_forwarded_fixture(original_frame.as_slice());
    mac.radio_mut().queue_received_frame(forwarded_frame.as_slice());

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let pending = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap();
    assert_eq!(pending.state, AckState::AwaitingAck);
}

#[test]
fn receive_one_repeater_forwards_source_routed_unicast_and_rewrites_options() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac.identity(repeater_id).unwrap().identity().public_key().router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let dst = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    let trace = [RouterHint([0x33, 0x44])];
    let source_route = [repeater_hint, RouterHint([0x21, 0x22])];

    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst,
        b"hello",
        false,
        None,
        Some(&trace),
        Some(&source_route),
    );

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(forwarded.priority, TxPriority::Forward);
    assert_eq!(forwarded.not_before_ms, 123);

    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let mut seen_trace = None;
    let mut seen_source_route = None;
    for entry in iter_options(forwarded.frame.as_slice(), header.options_range.clone()) {
        let (number, value) = entry.unwrap();
        match OptionNumber::from(number) {
            OptionNumber::TraceRoute => seen_trace = Some(value.to_vec()),
            OptionNumber::SourceRoute => seen_source_route = Some(value.to_vec()),
            _ => {}
        }
    }

    assert_eq!(seen_trace, Some([repeater_hint.0.as_slice(), trace[0].0.as_slice()].concat()));
    assert_eq!(seen_source_route, Some(source_route[1].0.to_vec()));
}

#[test]
fn receive_one_repeater_flood_forwards_with_delay_and_decrements_hops() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.add_channel(channel_key).unwrap();

    mac.radio_mut()
        .queue_received_multicast_with_flood(&remote, channel_id, &keys, b"group", Some((4, 2)));

    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(mac.dup_cache().len(), 1);
    assert_eq!(mac.tx_queue().len(), 1);
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(forwarded.priority, TxPriority::Forward);
    assert!(forwarded.not_before_ms >= 123);
    assert!(forwarded.not_before_ms <= 223);

    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    assert_eq!(header.flood_hops.unwrap(), FloodHops::new(3, 3).unwrap());
}

#[test]
fn receive_one_cancels_pending_forward_when_duplicate_is_overheard() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac.identity(repeater_id).unwrap().identity().public_key().router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    let frame = build_received_unicast_frame(
        &remote,
        &keys,
        &umsh_core::NodeHint([0x77, 0x66, 0x55]),
        b"hello",
        false,
        Some((4, 0)),
        None,
        Some(&[repeater_hint]),
    );

    mac.radio_mut().queue_received_frame(frame.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    mac.radio_mut().queue_received_frame(frame.as_slice());
    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(!handled);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn poll_cycle_holds_application_tx_while_forward_listen_is_active() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let route = [RouterHint([1, 2])];
    let options = SendOptions::default().with_ack_requested(true).try_with_source_route(&route).unwrap();
    let receipt = mac.queue_unicast(local_id, &peer_key, b"hello", &options).unwrap().unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"later", None).unwrap();

    block_on(mac.poll_cycle(|_, _| {})).unwrap();

    assert_eq!(mac.radio().transmitted.len(), 1);
    assert_eq!(mac.tx_queue().len(), 1);
    assert_eq!(mac.tx_queue_mut().pop_next().unwrap().frame.as_slice(), b"later");
    assert!(matches!(
        mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().state,
        AckState::AwaitingForward { .. }
    ));
}

#[test]
fn drain_tx_queue_returns_when_cad_keeps_reporting_busy() {
    let mut mac = make_mac();
    mac.radio_mut().cad_responses.push_back(true).unwrap();
    mac.tx_queue_mut().enqueue(TxPriority::Application, b"app", None).unwrap();

    block_on(mac.drain_tx_queue()).unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    assert!(mac.radio().transmitted.is_empty());
    assert_eq!(mac.radio().cad_calls, 1);
}

#[test]
fn poll_cycle_drains_tx_receives_unicast_and_sends_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key);
    let keys = PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
    let dst_hint = mac.identity(local_id).unwrap().identity().public_key().hint();

    mac.tx_queue_mut().enqueue(TxPriority::Application, b"queued", None).unwrap();
    mac.radio_mut().queue_received_unicast(&remote, &keys, &dst_hint, b"hello", true);

    let mut seen = None;
    block_on(mac.poll_cycle(|identity, event| {
        if let MacEventRef::Unicast { from, payload, ack_requested } = event {
            seen = Some((identity, from, payload.to_vec(), ack_requested));
        }
    }))
    .unwrap();

    assert_eq!(seen, Some((local_id, peer_key, b"hello".to_vec(), true)));
    assert_eq!(mac.radio().transmitted.len(), 2);
    assert_eq!(mac.radio().transmitted[0].as_slice(), b"queued");
    let ack_header = PacketHeader::parse(mac.radio().transmitted[1].as_slice()).unwrap();
    assert_eq!(ack_header.fcf.packet_type(), PacketType::MacAck);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn poll_cycle_emits_ack_timeout_after_receive_phase() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next();
    mac.identity_mut(local_id).unwrap().pending_ack_mut(&receipt).unwrap().ack_deadline_ms = 0;

    let mut seen = None;
    block_on(mac.poll_cycle(|identity, event| {
        if let MacEventRef::AckTimeout { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    }))
    .unwrap();

    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

#[test]
fn confirmed_forwarded_send_no_longer_retries_on_confirmation_timeout() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let route = [RouterHint([1, 2])];
    let options = SendOptions::default().with_ack_requested(true).try_with_source_route(&route).unwrap();
    let receipt = mac.queue_unicast(local_id, &peer_key, b"hello", &options).unwrap().unwrap();
    let _ = block_on(mac.transmit_next()).unwrap();
    let original_frame = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().resend.frame.clone();
    mac.radio_mut().queue_received_frame(original_frame.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    let pending = mac.identity_mut(local_id).unwrap().pending_ack_mut(&receipt).unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 999_999;

    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();

    assert!(mac.tx_queue().is_empty());
}

#[test]
fn forwarded_send_can_confirm_then_complete_on_later_mac_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let route = [RouterHint([1, 2])];
    let options = SendOptions::default().with_ack_requested(true).try_with_source_route(&route).unwrap();
    let receipt = mac.queue_unicast(local_id, &peer_key, b"hello", &options).unwrap().unwrap();
    let _ = block_on(mac.transmit_next()).unwrap();

    let original_frame = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().resend.frame.clone();
    let forwarded_frame = rewrite_forwarded_fixture(original_frame.as_slice());
    mac.radio_mut().queue_received_frame(forwarded_frame.as_slice());
    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(handled);
    assert!(matches!(
        mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().state,
        AckState::AwaitingAck
    ));

    let ack_tag = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().ack_tag;
    let dst = mac.identity(local_id).unwrap().identity().public_key().router_hint();
    mac.radio_mut().queue_received_mac_ack(dst, ack_tag);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::AckReceived { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

#[test]
fn poll_cycle_prefers_mac_ack_over_same_cycle_timeout() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    let ack_tag = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().ack_tag;
    let dst = mac.identity(local_id).unwrap().identity().public_key().router_hint();

    let _ = mac.tx_queue_mut().pop_next();
    mac.identity_mut(local_id).unwrap().pending_ack_mut(&receipt).unwrap().ack_deadline_ms = 0;
    mac.radio_mut().queue_received_mac_ack(dst, ack_tag);

    let mut ack_seen = None;
    let mut timeout_seen = None;
    block_on(mac.poll_cycle(|identity, event| match event {
        MacEventRef::AckReceived { peer, receipt } => ack_seen = Some((identity, peer, receipt)),
        MacEventRef::AckTimeout { peer, receipt } => timeout_seen = Some((identity, peer, receipt)),
        _ => {}
    }))
    .unwrap();

    assert_eq!(ack_seen, Some((local_id, peer_key, receipt)));
    assert_eq!(timeout_seen, None);
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

#[test]
fn send_receipts_wrap_from_u32_max_back_to_zero() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();
    mac.identity_mut(local_id).unwrap().set_next_receipt_for_test(u32::MAX);

    let first = mac
        .queue_unicast(local_id, &peer_key, b"first", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    let second = mac
        .queue_unicast(local_id, &peer_key, b"second", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();

    assert_eq!(first, SendReceipt(u32::MAX));
    assert_eq!(second, SendReceipt(0));
    assert!(mac.identity(local_id).unwrap().pending_ack(&first).is_some());
    assert!(mac.identity(local_id).unwrap().pending_ack(&second).is_some());
}

#[test]
fn service_pending_ack_timeouts_emits_timeout_and_removes_entry() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next();
    let pending = mac.identity_mut(local_id).unwrap().pending_ack_mut(&receipt).unwrap();
    pending.ack_deadline_ms = 0;

    let mut seen = None;
    mac.service_pending_ack_timeouts(|identity, event| {
        if let MacEventRef::AckTimeout { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    }).unwrap();

    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

#[test]
fn service_pending_ack_timeouts_requeues_forwarded_retry() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let route = [RouterHint([1, 2])];
    let options = SendOptions::default().with_ack_requested(true).try_with_source_route(&route).unwrap();
    let receipt = mac.queue_unicast(local_id, &peer_key, b"hello", &options).unwrap().unwrap();
    mac.tx_queue_mut().pop_next();

    let pending = mac.identity_mut(local_id).unwrap().pending_ack_mut(&receipt).unwrap();
    pending.state = AckState::AwaitingForward { confirm_deadline_ms: 0 };

    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();

    let retry = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(retry.priority, TxPriority::Retry);
    assert_eq!(retry.receipt, Some(receipt));

    let pending = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap();
    assert_eq!(pending.retries, 1);
    assert!(matches!(pending.state, AckState::AwaitingForward { .. }));
}

#[test]
fn complete_ack_matches_receipt_and_clears_pending_entry() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key);
    mac.install_pairwise_keys(local_id, peer_id, PairwiseKeys { k_enc: [1; 16], k_mic: [2; 16] }).unwrap();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default().with_ack_requested(true).no_flood())
        .unwrap()
        .unwrap();
    let ack_tag = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap().ack_tag;

    assert_eq!(mac.complete_ack(&peer_key, &ack_tag), Some((local_id, receipt)));
    assert!(mac.identity(local_id).unwrap().pending_ack(&receipt).is_none());
}

fn make_mac() -> Mac<DummyRadio, DummyIdentity, DummyAes, DummySha, DummyClock, DummyRng, DummyCounterStore> {
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(DummyAes, DummySha),
        DummyClock { now_ms: Cell::new(123) },
        DummyRng(7),
        DummyCounterStore,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn make_small_peer_mac<const PEERS: usize>() -> Mac<DummyRadio, DummyIdentity, DummyAes, DummySha, DummyClock, DummyRng, DummyCounterStore, 4, PEERS, 8, 16, 16, 256, 64> {
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(DummyAes, DummySha),
        DummyClock { now_ms: Cell::new(123) },
        DummyRng(7),
        DummyCounterStore,
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn rewrite_forwarded_fixture(frame: &[u8]) -> heapless::Vec<u8, 256> {
    let mut stored = heapless::Vec::new();
    for byte in frame {
        stored.push(*byte).unwrap();
    }

    let header = PacketHeader::parse(stored.as_slice()).unwrap();
    if let Some(flood_hops) = header.flood_hops {
        stored[header.options_range.end] = flood_hops.decremented().0;
    }

    stored
}

fn build_received_unicast_frame(
    source: &DummyIdentity,
    keys: &PairwiseKeys,
    dst: &umsh_core::NodeHint,
    payload: &[u8],
    ack_requested: bool,
    flood_hops: Option<(u8, u8)>,
    trace_route: Option<&[RouterHint]>,
    source_route: Option<&[RouterHint]>,
) -> heapless::Vec<u8, 256> {
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf)
        .unicast(*dst)
        .source_full(source.public_key())
        .frame_counter(7)
        .encrypted();
    let builder = if ack_requested { builder.ack_requested() } else { builder };
    let builder = if let Some((remaining, _)) = flood_hops {
        builder.flood_hops(remaining)
    } else {
        builder
    };
    let builder = if let Some(route) = trace_route {
        let mut encoded = [0u8; 30];
        let mut used = 0usize;
        for hop in route {
            encoded[used..used + 2].copy_from_slice(&hop.0);
            used += 2;
        }
        builder.option(OptionNumber::TraceRoute, &encoded[..used])
    } else {
        builder
    };
    let builder = if let Some(route) = source_route {
        builder.source_route(route)
    } else {
        builder
    };

    let mut packet = builder.payload(payload).build().unwrap();
    if let Some((remaining, accumulated)) = flood_hops {
        let header = packet.header();
        packet.as_bytes_mut()[header.options_range.end] = FloodHops::new(remaining, accumulated).unwrap().0;
    }
    CryptoEngine::new(DummyAes, DummySha).seal_packet(&mut packet, keys).unwrap();

    let mut stored = heapless::Vec::new();
    for byte in packet.as_bytes() {
        stored.push(*byte).unwrap();
    }
    stored
}

fn build_received_blind_unicast_frame(
    source: &DummyIdentity,
    pairwise: &PairwiseKeys,
    channel_keys: &DerivedChannelKeys,
    dst: &umsh_core::NodeHint,
    payload: &[u8],
    ack_requested: bool,
    source_route: Option<&[RouterHint]>,
) -> heapless::Vec<u8, 256> {
    let engine = CryptoEngine::new(DummyAes, DummySha);
    let blind_keys = engine.derive_blind_keys(pairwise, channel_keys);
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf)
        .blind_unicast(channel_keys.channel_id, *dst)
        .source_full(source.public_key())
        .frame_counter(13);
    let builder = if ack_requested { builder.ack_requested() } else { builder };
    let builder = if let Some(route) = source_route {
        builder.source_route(route)
    } else {
        builder
    };
    let mut packet = builder.payload(payload).build().unwrap();
    engine
        .seal_blind_packet(&mut packet, &blind_keys, channel_keys)
        .unwrap();

    let mut stored = heapless::Vec::new();
    for byte in packet.as_bytes() {
        stored.push(*byte).unwrap();
    }
    stored
}

fn block_on<F: Future>(future: F) -> F::Output {
    fn noop_raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        RawWaker::new(core::ptr::null(), &RawWakerVTable::new(clone, wake, wake_by_ref, drop))
    }

    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match Future::poll(future.as_mut(), &mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

struct DummyIdentity { public_key: PublicKey }
impl DummyIdentity { fn new(bytes: [u8; 32]) -> Self { Self { public_key: PublicKey(bytes) } } }

impl NodeIdentity for DummyIdentity {
    type Error = ();
    fn public_key(&self) -> &PublicKey { &self.public_key }
    async fn sign(&self, _message: &[u8]) -> Result<[u8; 64], Self::Error> { Ok([0u8; 64]) }
    async fn agree(&self, _peer: &PublicKey) -> Result<SharedSecret, Self::Error> { Ok(SharedSecret([0u8; 32])) }
}

struct DummyCipher;
impl AesCipher for DummyCipher { fn encrypt_block(&self, _block: &mut [u8; 16]) {} fn decrypt_block(&self, _block: &mut [u8; 16]) {} }

struct DummyAes;
impl AesProvider for DummyAes { type Cipher = DummyCipher; fn new_cipher(&self, _key: &[u8; 16]) -> Self::Cipher { DummyCipher } }

struct DummySha;
impl Sha256Provider for DummySha {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32] { let mut out = [0u8; 32]; out[0] = data.iter().map(|chunk| chunk.len() as u8).fold(0, u8::wrapping_add); out }
    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32] { let mut out = [0u8; 32]; out[0] = key.len() as u8; out[1] = data.iter().map(|chunk| chunk.len() as u8).fold(0, u8::wrapping_add); out }
}

#[derive(Default)]
struct DummyRadio {
    transmitted: heapless::Vec<heapless::Vec<u8, 256>, 16>,
    cad_responses: heapless::Deque<bool, 16>,
    cad_calls: u32,
    received: heapless::Deque<heapless::Vec<u8, 256>, 16>,
}

impl DummyRadio {
    fn queue_received_broadcast(&mut self, source: &DummyIdentity, payload: &[u8]) {
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_full(source.public_key())
            .payload(payload)
            .build()
            .unwrap();
        self.queue_received_frame(&frame);
    }

    fn queue_received_mac_ack(&mut self, dst: RouterHint, ack_tag: [u8; 8]) {
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf).mac_ack(dst.0, ack_tag).build().unwrap();
        let mut stored = heapless::Vec::new();
        for byte in frame {
            stored.push(*byte).unwrap();
        }
        self.received.push_back(stored).unwrap();
    }

    fn queue_received_unicast(
        &mut self,
        source: &DummyIdentity,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
    ) {
        self.queue_received_unicast_with_route(source, keys, dst, payload, ack_requested, None, None, None);
    }

    fn queue_received_unicast_with_source_hint(
        &mut self,
        source: umsh_core::NodeHint,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
    ) {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .unicast(*dst)
            .source_hint(source)
            .frame_counter(7)
            .encrypted();
        let builder = if ack_requested { builder.ack_requested() } else { builder };
        let mut packet = builder.payload(payload).build().unwrap();
        CryptoEngine::new(DummyAes, DummySha).seal_packet(&mut packet, keys).unwrap();
        self.queue_received_frame(packet.as_bytes());
    }

    fn queue_received_unicast_with_route(
        &mut self,
        source: &DummyIdentity,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
        flood_hops: Option<(u8, u8)>,
        trace_route: Option<&[RouterHint]>,
        source_route: Option<&[RouterHint]>,
    ) {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf).unicast(*dst).source_full(source.public_key()).frame_counter(7).encrypted();
        let builder = if ack_requested { builder.ack_requested() } else { builder };
        let builder = if let Some((remaining, _accumulated)) = flood_hops {
            builder.flood_hops(remaining)
        } else {
            builder
        };
        let builder = if let Some(route) = trace_route {
            let mut encoded = [0u8; 30];
            let mut used = 0usize;
            for hop in route {
                encoded[used..used + 2].copy_from_slice(&hop.0);
                used += 2;
            }
            builder.option(OptionNumber::TraceRoute, &encoded[..used])
        } else {
            builder
        };
        let builder = if let Some(route) = source_route {
            builder.source_route(route)
        } else {
            builder
        };
        let mut packet = builder.payload(payload).build().unwrap();
        if let Some((remaining, accumulated)) = flood_hops {
            let header = packet.header();
            packet.as_bytes_mut()[header.options_range.end] = FloodHops::new(remaining, accumulated).unwrap().0;
        }
        CryptoEngine::new(DummyAes, DummySha).seal_packet(&mut packet, keys).unwrap();
        let mut stored = heapless::Vec::new();
        for byte in packet.as_bytes() {
            stored.push(*byte).unwrap();
        }
        self.received.push_back(stored).unwrap();
    }

    fn queue_received_frame(&mut self, frame: &[u8]) {
        let mut stored = heapless::Vec::new();
        for byte in frame {
            stored.push(*byte).unwrap();
        }
        self.received.push_back(stored).unwrap();
    }

    fn queue_received_blind_unicast(
        &mut self,
        source: &DummyIdentity,
        pairwise: &PairwiseKeys,
        channel_keys: &DerivedChannelKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
    ) {
        self.queue_received_blind_unicast_with_route(source, pairwise, channel_keys, dst, payload, ack_requested, None);
    }

    fn queue_received_blind_unicast_with_source_hint(
        &mut self,
        source: umsh_core::NodeHint,
        pairwise: &PairwiseKeys,
        channel_keys: &DerivedChannelKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
    ) {
        let engine = CryptoEngine::new(DummyAes, DummySha);
        let blind_keys = engine.derive_blind_keys(pairwise, channel_keys);
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .blind_unicast(channel_keys.channel_id, *dst)
            .source_hint(source)
            .frame_counter(13);
        let builder = if ack_requested { builder.ack_requested() } else { builder };
        let mut packet = builder.payload(payload).build().unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, channel_keys)
            .unwrap();
        self.queue_received_frame(packet.as_bytes());
    }

    fn queue_received_unencrypted_blind_unicast(
        &mut self,
        source: &DummyIdentity,
        pairwise: &PairwiseKeys,
        channel_keys: &DerivedChannelKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
    ) {
        let engine = CryptoEngine::new(DummyAes, DummySha);
        let blind_keys = engine.derive_blind_keys(pairwise, channel_keys);
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .blind_unicast(channel_keys.channel_id, *dst)
            .source_full(source.public_key())
            .frame_counter(13)
            .unencrypted();
        let builder = if ack_requested { builder.ack_requested() } else { builder };
        let mut packet = builder.payload(payload).build().unwrap();
        engine.seal_blind_packet(&mut packet, &blind_keys, channel_keys).unwrap();
        self.queue_received_frame(packet.as_bytes());
    }

    fn queue_received_blind_unicast_with_route(
        &mut self,
        source: &DummyIdentity,
        pairwise: &PairwiseKeys,
        channel_keys: &DerivedChannelKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
        source_route: Option<&[RouterHint]>,
    ) {
        let engine = CryptoEngine::new(DummyAes, DummySha);
        let blind_keys = engine.derive_blind_keys(pairwise, channel_keys);
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .blind_unicast(channel_keys.channel_id, *dst)
            .source_full(source.public_key())
            .frame_counter(13);
        let builder = if ack_requested { builder.ack_requested() } else { builder };
        let builder = if let Some(route) = source_route {
            builder.source_route(route)
        } else {
            builder
        };
        let mut packet = builder.payload(payload).build().unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, channel_keys)
            .unwrap();
        self.queue_received_frame(packet.as_bytes());
    }

    fn queue_received_multicast(
        &mut self,
        source: &DummyIdentity,
        channel_id: ChannelId,
        keys: &PairwiseKeys,
        payload: &[u8],
    ) {
        self.queue_received_multicast_with_flood(source, channel_id, keys, payload, None);
    }

    fn queue_received_multicast_with_flood(
        &mut self,
        source: &DummyIdentity,
        channel_id: ChannelId,
        keys: &PairwiseKeys,
        payload: &[u8],
        flood_hops: Option<(u8, u8)>,
    ) {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .multicast(channel_id)
            .source_full(source.public_key())
            .frame_counter(11)
            .encrypted();
        let builder = if let Some((remaining, _accumulated)) = flood_hops {
            builder.flood_hops(remaining)
        } else {
            builder
        };
        let mut packet = builder.payload(payload).build().unwrap();
        if let Some((remaining, accumulated)) = flood_hops {
            let header = packet.header();
            packet.as_bytes_mut()[header.options_range.end] = FloodHops::new(remaining, accumulated).unwrap().0;
        }
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, keys)
            .unwrap();
        self.queue_received_frame(packet.as_bytes());
    }
}

impl Radio for DummyRadio {
    type Error = ();
    async fn transmit(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut stored = heapless::Vec::new();
        for byte in data {
            stored.push(*byte).unwrap();
        }
        self.transmitted.push(stored).unwrap();
        Ok(())
    }
    async fn receive(&mut self, buf: &mut [u8]) -> Result<RxInfo, Self::Error> {
        let Some(frame) = self.received.pop_front() else {
            return Ok(RxInfo { len: 0, rssi: 0, snr: 0 });
        };
        buf[..frame.len()].copy_from_slice(frame.as_slice());
        Ok(RxInfo { len: frame.len(), rssi: 0, snr: 0 })
    }
    async fn cad(&mut self) -> Result<bool, Self::Error> {
        self.cad_calls = self.cad_calls.wrapping_add(1);
        Ok(self.cad_responses.pop_front().unwrap_or(false))
    }
    fn max_frame_size(&self) -> usize { 255 }
    fn t_frame_ms(&self) -> u32 { 100 }
}

struct DummyClock {
    now_ms: Cell<u64>,
}

impl DummyClock {
    fn advance_ms(&self, delta_ms: u64) {
        self.now_ms.set(self.now_ms.get().saturating_add(delta_ms));
    }
}

impl Clock for DummyClock { fn now_ms(&self) -> u64 { self.now_ms.get() } }

struct DummyRng(u8);
impl Rng for DummyRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() { *byte = self.0; self.0 = self.0.wrapping_add(1); }
    }
}

struct DummyCounterStore;
impl CounterStore for DummyCounterStore {
    type Error = ();
    async fn load(&self, _context: &[u8]) -> Result<u32, Self::Error> { Ok(0) }
    async fn store(&self, _context: &[u8], _value: u32) -> Result<(), Self::Error> { Ok(()) }
    async fn flush(&self) -> Result<(), Self::Error> { Ok(()) }
}