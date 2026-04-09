use super::*;
use core::convert::Infallible;
use core::{
    cell::{Cell, RefCell},
    future::Future,
    pin::pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use embedded_hal_async::delay::DelayNs;
use hamaddr::HamAddr;
use rand::{Rng, TryCryptoRng, TryRng};
use std::collections::BTreeMap;
use umsh_core::{
    ChannelId, ChannelKey, FloodHops, NodeHint, OptionNumber, PacketBuilder, PacketHeader,
    PacketType, ParsedOptions, PayloadType, PublicKey, RouterHint, iter_options,
};
use umsh_crypto::{
    AesCipher, AesProvider, CryptoEngine, DerivedChannelKeys, NodeIdentity, PairwiseKeys,
    Sha256Provider, SharedSecret,
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, Snr, TxError, TxOptions};

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
fn route_retry_changes_authenticated_duplicate_key_without_changing_mic() {
    let source = DummyIdentity::new([0x11; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let dst = NodeHint([0xAA, 0xBB, 0xCC]);

    let build = |route_retry: bool| {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .unicast(dst)
            .source_full(source.public_key())
            .frame_counter(7)
            .encrypted()
            .mic_size(umsh_core::MicSize::Mic16)
            .option(OptionNumber::TraceRoute, &[]);
        let builder = if route_retry {
            builder.option(OptionNumber::RouteRetry, &[])
        } else {
            builder
        };
        let mut packet = builder.payload(b"hello").build().unwrap();
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, &keys)
            .unwrap();
        let mut stored: heapless::Vec<u8, 256> = heapless::Vec::new();
        stored.extend_from_slice(packet.as_bytes()).unwrap();
        stored
    };

    let plain = build(false);
    let retried = build(true);
    let plain_header = PacketHeader::parse(plain.as_slice()).unwrap();
    let retried_header = PacketHeader::parse(retried.as_slice()).unwrap();

    assert_eq!(
        &plain.as_slice()[plain_header.mic_range.clone()],
        &retried.as_slice()[retried_header.mic_range.clone()]
    );

    let key_plain = duplicate_key_for_secure_frame(plain.as_slice());
    let key_retried = duplicate_key_for_secure_frame(retried.as_slice());

    assert_ne!(key_plain, key_retried);
}

#[test]
fn mac_ack_duplicate_key_ignores_dynamic_forwarding_fields() {
    let mut direct = [0u8; 256];
    let direct = PacketBuilder::new(&mut direct)
        .mac_ack(NodeHint([0x12, 0x34, 0x56]), [0xA5; 8])
        .build()
        .unwrap();
    let mut routed = [0u8; 256];
    let routed = PacketBuilder::new(&mut routed)
        .mac_ack(NodeHint([0x12, 0x34, 0x56]), [0xA5; 8])
        .option(OptionNumber::TraceRoute, &[0x09, 0x08])
        .source_route(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])])
        .flood_hops(2)
        .build()
        .unwrap();

    let direct_header = PacketHeader::parse(direct).unwrap();
    let routed_header = PacketHeader::parse(routed).unwrap();

    assert_eq!(
        super::Mac::<DummyPlatform, 4, 16, 8, 16, 16, 256, 64>::forward_dup_key(
            &direct_header,
            direct
        ),
        super::Mac::<DummyPlatform, 4, 16, 8, 16, 16, 256, 64>::forward_dup_key(
            &routed_header,
            routed
        )
    );
}

#[test]
fn forward_duplicate_key_exists_for_every_routable_packet_class() {
    let source = DummyIdentity::new([0x11; 32]);
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let crypto = CryptoEngine::new(DummyAes, DummySha);
    let channel_keys = crypto.derive_channel_keys(&channel_key);
    let dst = NodeHint([0xAA, 0xBB, 0xCC]);

    let mut broadcast = [0u8; 256];
    let broadcast = PacketBuilder::new(&mut broadcast)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(2)
        .payload(b"hello")
        .build()
        .unwrap();

    let mut mac_ack = [0u8; 256];
    let mac_ack = PacketBuilder::new(&mut mac_ack)
        .mac_ack(dst, [0xA5; 8])
        .source_route(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])])
        .build()
        .unwrap();

    let unicast = build_received_unicast_frame(
        &source,
        &pairwise,
        &dst,
        b"hello",
        false,
        Some((2, 0)),
        Some(&[RouterHint([0x09, 0x08])]),
        Some(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])]),
    );

    let blind_unicast = build_received_blind_unicast_frame(
        &source,
        &pairwise,
        &channel_keys,
        &dst,
        b"hello",
        false,
        Some(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])]),
    );

    let mut multicast = [0u8; 256];
    let mut multicast = PacketBuilder::new(&mut multicast)
        .multicast(channel_keys.channel_id)
        .source_full(source.public_key())
        .frame_counter(11)
        .encrypted()
        .flood_hops(2)
        .payload(b"group")
        .build()
        .unwrap();
    {
        let header = multicast.header().unwrap();
        multicast.as_bytes_mut()[header.options_range.end] = FloodHops::new(2, 0).unwrap().0;
    }
    crypto.seal_packet(&mut multicast, &pairwise).unwrap();

    for frame in [
        broadcast,
        mac_ack,
        unicast.as_slice(),
        blind_unicast.as_slice(),
        multicast.as_bytes(),
    ] {
        let header = PacketHeader::parse(frame).unwrap();
        assert!(
            super::Mac::<DummyPlatform, 4, 16, 8, 16, 16, 256, 64>::forward_dup_key(&header, frame)
                .is_some(),
            "routable packet {:?} should have a forwarding duplicate identity",
            header.packet_type()
        );
    }
}

#[test]
fn confirmation_identity_matches_forwarding_identity_for_every_routable_packet_class() {
    let source = DummyIdentity::new([0x11; 32]);
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let crypto = CryptoEngine::new(DummyAes, DummySha);
    let channel_keys = crypto.derive_channel_keys(&channel_key);
    let dst = NodeHint([0xAA, 0xBB, 0xCC]);

    let mut broadcast = [0u8; 256];
    let broadcast = PacketBuilder::new(&mut broadcast)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(2)
        .payload(b"hello")
        .build()
        .unwrap();

    let mut mac_ack = [0u8; 256];
    let mac_ack = PacketBuilder::new(&mut mac_ack)
        .mac_ack(dst, [0xA5; 8])
        .source_route(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])])
        .build()
        .unwrap();

    let unicast = build_received_unicast_frame(
        &source,
        &pairwise,
        &dst,
        b"hello",
        true,
        Some((2, 0)),
        Some(&[RouterHint([0x09, 0x08])]),
        Some(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])]),
    );

    let blind_unicast = build_received_blind_unicast_frame(
        &source,
        &pairwise,
        &channel_keys,
        &dst,
        b"hello",
        true,
        Some(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])]),
    );

    let mut multicast = [0u8; 256];
    let mut multicast = PacketBuilder::new(&mut multicast)
        .multicast(channel_keys.channel_id)
        .source_full(source.public_key())
        .frame_counter(11)
        .encrypted()
        .flood_hops(2)
        .payload(b"group")
        .build()
        .unwrap();
    {
        let header = multicast.header().unwrap();
        multicast.as_bytes_mut()[header.options_range.end] = FloodHops::new(2, 0).unwrap().0;
    }
    crypto.seal_packet(&mut multicast, &pairwise).unwrap();

    for frame in [
        broadcast,
        mac_ack,
        unicast.as_slice(),
        blind_unicast.as_slice(),
        multicast.as_bytes(),
    ] {
        let header = PacketHeader::parse(frame).unwrap();
        assert_eq!(
            super::Mac::<DummyPlatform, 4, 16, 8, 16, 16, 256, 64>::forward_dup_key(&header, frame),
            super::Mac::<DummyPlatform, 4, 16, 8, 16, 16, 256, 64>::confirmation_key(frame),
            "routable packet {:?} should use one shared forwarding/confirmation identity",
            header.packet_type()
        );
    }
}

#[test]
fn replay_window_detects_replay_and_window_expiry() {
    let mut window = ReplayWindow::new();
    let mic = [0x11u8; 8];

    assert_eq!(window.check(10, &mic, 1), ReplayVerdict::Accept);
    window.accept(10, &mic, 1);
    assert_eq!(window.check(10, &mic, 2), ReplayVerdict::Replay);
    assert_eq!(window.check(1, &mic, 2), ReplayVerdict::OutOfWindow);
    assert_eq!(
        window.check(10, &mic, crate::REPLAY_STALE_MS + 2),
        ReplayVerdict::Stale
    );
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
fn replay_window_rejects_replay_after_recent_mic_eviction() {
    let mut window = ReplayWindow::new();

    for counter in 10..=18 {
        let mic = [counter as u8; 8];
        assert_eq!(
            window.check(counter, &mic, counter as u64),
            ReplayVerdict::Accept
        );
        window.accept(counter, &mic, counter as u64);
    }

    assert_eq!(window.recent_mics.len(), crate::RECENT_MIC_CAPACITY);
    assert_eq!(window.check(10, &[10u8; 8], 20), ReplayVerdict::Replay);
}

#[test]
fn receive_one_auto_replies_to_echo_request() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_id = mac.add_peer(*remote.public_key()).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let request = encode_echo_command_payload(4, &[9, 8, 7, 6]);
    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, &request, false);

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let response = mac.tx_queue_mut().pop_next().expect("echo response queued");
    let payload = decrypt_unicast_payload(response.frame.as_slice(), &keys);
    assert_eq!(
        payload.as_slice(),
        encode_echo_command_payload(5, &[9, 8, 7, 6]).as_slice()
    );
}

#[test]
fn peer_registry_looks_up_by_hint_and_updates_route() {
    let mut registry = PeerRegistry::<4>::new();
    let key = PublicKey([0xA1; 32]);
    let peer_id = registry.try_insert_or_update(key).unwrap();

    let matches: heapless::Vec<PeerId, 4> = registry
        .lookup_by_hint(&key.hint())
        .map(|(id, _)| id)
        .collect();
    assert_eq!(matches.as_slice(), &[peer_id]);

    let mut route = heapless::Vec::new();
    route.push(RouterHint([1, 2])).unwrap();
    registry.update_route(peer_id, CachedRoute::Source(route.clone()));
    assert_eq!(
        registry.get(peer_id).unwrap().route,
        Some(CachedRoute::Source(route))
    );
}

#[test]
fn channel_table_updates_existing_channel() {
    let mut table = ChannelTable::<2>::new();
    let key_a = ChannelKey([0x11; 32]);
    let key_b = ChannelKey([0x22; 32]);
    let derived_a = umsh_crypto::DerivedChannelKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
        channel_id: ChannelId([0xAA, 0xBB]),
    };
    let derived_b = umsh_crypto::DerivedChannelKeys {
        k_enc: [3; 16],
        k_mic: [4; 16],
        channel_id: ChannelId([0xAA, 0xBB]),
    };

    table.try_add(key_a, derived_a).unwrap();
    table.try_add(key_b.clone(), derived_b.clone()).unwrap();

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
    let options = SendOptions::default()
        .try_with_source_route(&route)
        .unwrap();
    assert_eq!(options.source_route.unwrap().as_slice(), &route);

    let too_long = [RouterHint([9, 9]); crate::MAX_SOURCE_ROUTE_HOPS + 1];
    assert_eq!(
        SendOptions::default().try_with_source_route(&too_long),
        Err(CapacityError)
    );
}

#[test]
fn direct_ack_requested_starts_awaiting_ack() {
    let resend: ResendRecord = ResendRecord::try_new(b"hello", None).unwrap();
    let pending = PendingAck::direct([0xAA; 8], PublicKey([0x11; 32]), resend);
    assert_eq!(
        pending.state,
        AckState::Queued {
            needs_forward_confirmation: false
        }
    );
}

#[test]
fn forwarded_ack_requested_starts_awaiting_forward() {
    let resend: ResendRecord =
        ResendRecord::try_new(b"hello", Some(&[RouterHint([1, 2])])).unwrap();
    let pending = PendingAck::forwarded([0xBB; 8], PublicKey([0x22; 32]), resend);
    assert_eq!(
        pending.state,
        AckState::Queued {
            needs_forward_confirmation: true
        }
    );
}

#[test]
fn tx_queue_pops_highest_priority_first_then_fifo_within_priority() {
    let mut queue = TxQueue::<8>::new();
    queue
        .enqueue(TxPriority::Application, b"app-a", None, None)
        .unwrap();
    queue
        .enqueue(TxPriority::Retry, b"retry", Some(SendReceipt(1)), None)
        .unwrap();
    queue
        .enqueue(TxPriority::ImmediateAck, b"ack", None, None)
        .unwrap();
    queue
        .enqueue(TxPriority::Application, b"app-b", None, None)
        .unwrap();

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
    slot.try_insert_pending_ack(
        receipt,
        PendingAck::direct([0xAA; 8], PublicKey([1; 32]), resend.clone()),
    )
    .unwrap();
    let second_receipt = slot.next_receipt();

    assert_eq!(
        slot.try_insert_pending_ack(
            second_receipt,
            PendingAck::direct([0xBB; 8], PublicKey([2; 32]), resend)
        ),
        Err(PendingAckError::TableFull)
    );
}

#[test]
fn mac_adds_identities_peers_and_channels() {
    let mut mac = make_mac();

    let id_a = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let id_b = mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();
    let peer = mac.add_peer(PublicKey([0xAB; 32])).unwrap();
    mac.add_channel(ChannelKey([0x5A; 32])).unwrap();

    assert_eq!(id_a, LocalIdentityId(0));
    assert_eq!(id_b, LocalIdentityId(1));
    assert_eq!(mac.identity_count(), 2);
    assert_eq!(
        mac.identity(id_b).unwrap().identity().hint(),
        umsh_core::NodeHint([0x20; 3])
    );
    assert_eq!(
        mac.peer_registry().get(peer).unwrap().public_key,
        PublicKey([0xAB; 32])
    );
    assert_eq!(mac.channels().len(), 1);
}

#[test]
fn new_identity_starts_with_random_frame_counter() {
    let mut mac = make_mac();

    let first_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let second_id = mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();

    assert_eq!(
        mac.identity(first_id).unwrap().frame_counter(),
        u32::from_le_bytes([7, 8, 9, 10])
    );
    assert_eq!(
        mac.identity(second_id).unwrap().frame_counter(),
        u32::from_le_bytes([11, 12, 13, 14])
    );
}

#[test]
fn persisted_counter_load_overrides_random_initial_counter() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    assert_eq!(
        mac.identity(local_id).unwrap().frame_counter(),
        u32::from_le_bytes([7, 8, 9, 10])
    );

    mac.counter_store()
        .loaded
        .borrow_mut()
        .insert(vec![0x10; 32], 128);

    let loaded = block_on(mac.load_persisted_counter(local_id)).unwrap();

    assert_eq!(loaded, 128);
    assert_eq!(mac.identity(local_id).unwrap().frame_counter(), 128);
}

#[cfg(feature = "software-crypto")]
#[test]
fn new_ephemeral_identity_starts_with_random_frame_counter() {
    let mut mac = make_mac();
    let parent_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let ephemeral = umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[0x55; 32]);

    let ephemeral_id = mac.register_ephemeral(parent_id, ephemeral).unwrap();

    assert_eq!(
        mac.identity(ephemeral_id).unwrap().frame_counter(),
        u32::from_le_bytes([11, 12, 13, 14])
    );
}

#[test]
fn queue_unicast_requires_installed_pairwise_keys() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let _peer_id = mac.add_peer(peer_key).unwrap();

    assert_eq!(
        mac.queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default()),
        Err(SendError::PairwiseKeysMissing)
    );
}

#[test]
fn queue_unicast_enqueues_frame_and_pending_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_some()
    );
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
        .install_pairwise_keys(
            local_id,
            peer_id,
            PairwiseKeys {
                k_enc: [1; 16],
                k_mic: [2; 16],
            },
        )
        .unwrap();

    let receipt = block_on(handle_clone.send_unicast(
        local_id,
        &peer_key,
        b"hello",
        &SendOptions::default().with_ack_requested(true).no_flood(),
    ))
    .unwrap()
    .unwrap();

    let borrowed = mac.borrow();
    assert_eq!(borrowed.tx_queue().len(), 1);
    assert!(
        borrowed
            .identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_some()
    );
}

#[test]
fn send_unicast_auto_derives_pairwise_state_on_first_contact() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();

    let receipt = block_on(mac.send_unicast(
        local_id,
        &peer_key,
        b"hello",
        &SendOptions::default().with_ack_requested(true).no_flood(),
    ))
    .unwrap()
    .unwrap();

    let slot = mac.identity(local_id).unwrap();
    let derived = slot.peer_crypto().get(&peer_id).unwrap();
    let expected = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    assert_eq!(derived.pairwise_keys.k_enc, expected.k_enc);
    assert_eq!(derived.pairwise_keys.k_mic, expected.k_mic);
    assert!(slot.pending_ack(&receipt).is_some());
    assert_eq!(mac.tx_queue().len(), 1);
}

#[test]
fn queue_blind_unicast_requires_known_channel() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    assert_eq!(
        mac.queue_blind_unicast(
            local_id,
            &peer_key,
            &ChannelId([0xAA, 0xBB]),
            b"hello",
            &SendOptions::default()
        ),
        Err(SendError::ChannelMissing)
    );
}

#[test]
fn licensed_only_mode_rejects_encrypted_unicast() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign =
        Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    assert_eq!(
        mac.queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().no_flood()
        ),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn licensed_only_mode_rejects_encrypted_blind_unicast() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign =
        Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.add_channel(channel_key).unwrap();

    assert_eq!(
        mac.queue_blind_unicast(
            local_id,
            &peer_key,
            &channel_id,
            b"hello",
            &SendOptions::default()
        ),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn licensed_only_mode_allows_unencrypted_blind_unicast_with_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign =
        Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.add_channel(channel_key).unwrap();

    assert!(
        mac.queue_blind_unicast(
            local_id,
            &peer_key,
            &channel_id,
            b"hello",
            &SendOptions::default().unencrypted()
        )
        .is_ok()
    );
}

#[test]
fn hybrid_mode_allows_encrypted_unicast_without_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::Hybrid;

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    assert!(
        mac.queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().no_flood()
        )
        .is_ok()
    );
}

#[test]
fn unlicensed_mode_allows_blind_unicast_without_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::Unlicensed;

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.add_channel(channel_key).unwrap();

    assert!(
        mac.queue_blind_unicast(
            local_id,
            &peer_key,
            &channel_id,
            b"hello",
            &SendOptions::default()
        )
        .is_ok()
    );
}

#[test]
fn queue_broadcast_injects_operator_callsign_option() {
    let mut mac = make_mac();
    mac.operating_policy_mut().operator_callsign =
        Some(HamAddr::try_from_callsign("KZ2X").unwrap());

    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.queue_broadcast(
        local_id,
        b"hello",
        &SendOptions::default().unencrypted().no_flood(),
    )
    .unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    let operator = iter_options(queued.frame.as_slice(), header.options_range)
        .find_map(|entry| match entry.unwrap() {
            (number, value) if OptionNumber::from(number) == OptionNumber::OperatorCallsign => {
                Some(value.to_vec())
            }
            _ => None,
        })
        .unwrap();

    assert_eq!(
        operator,
        HamAddr::try_from_callsign("KZ2X")
            .unwrap()
            .as_trimmed_slice()
    );
}

#[test]
fn receive_one_delivers_broadcast_to_all_identities() {
    let mut mac = make_mac();
    let id_a = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let id_b = mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);

    mac.radio_mut()
        .queue_received_broadcast(&remote, &[1, 0x44, 0x55]);

    let mut seen = heapless::Vec::<(LocalIdentityId, PublicKey, heapless::Vec<u8, 8>), 4>::new();
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Broadcast) {
            let mut body = heapless::Vec::new();
            for byte in packet.payload_bytes() {
                body.push(*byte).unwrap();
            }
            seen.push((identity, packet.from_key().unwrap(), body))
                .unwrap();
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

    mac.radio_mut()
        .queue_received_broadcast(&remote, &[3, b'h', b'i']);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::Broadcast) {
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
    let derived = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };

    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &derived, &[5, 0x01]);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::Multicast) {
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
        mac.queue_multicast(
            local_id,
            &channel_id,
            b"hello",
            &SendOptions::default().unencrypted()
        ),
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
        mac.queue_multicast(
            local_id,
            &channel_id,
            b"hello",
            &SendOptions::default().with_flood_hops(2).unencrypted()
        ),
        Err(SendError::PolicyViolation)
    );
}

#[test]
fn queue_blind_unicast_enqueues_frame_and_pending_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.add_channel(channel_key).unwrap();

    let receipt = mac
        .queue_blind_unicast(
            local_id,
            &peer_key,
            &channel_id,
            b"hello",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::BlindUnicastAckReq);
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_some()
    );
}

#[test]
fn queue_multicast_enqueues_frame_for_known_channel() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key).unwrap();

    mac.queue_multicast(local_id, &channel_id, b"hello", &SendOptions::default())
        .unwrap();
    assert_eq!(mac.tx_queue().len(), 1);
}

#[test]
fn queue_broadcast_does_not_advance_secure_frame_counter() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let initial_counter = mac.identity(local_id).unwrap().frame_counter();

    mac.queue_broadcast(
        local_id,
        b"hello",
        &SendOptions::default().unencrypted().no_flood(),
    )
    .unwrap();

    assert_eq!(
        mac.identity(local_id).unwrap().frame_counter(),
        initial_counter
    );
}

#[test]
fn first_secure_send_schedules_counter_persist() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let initial_counter = mac.identity(local_id).unwrap().frame_counter();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    mac.queue_unicast(
        local_id,
        &peer_key,
        b"hello",
        &SendOptions::default().no_flood(),
    )
    .unwrap();

    let advanced_counter = initial_counter.wrapping_add(1);
    let expected_target = advanced_counter.wrapping_add(128) & !127;

    assert_eq!(
        mac.identity(local_id).unwrap().frame_counter(),
        advanced_counter
    );
    assert_eq!(
        mac.identity(local_id).unwrap().pending_persist_target(),
        Some(expected_target)
    );
}

#[test]
fn counter_persist_threshold_schedules_next_block() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let initial_counter = mac.identity(local_id).unwrap().frame_counter();
    mac.queue_unicast(
        local_id,
        &peer_key,
        b"hello",
        &SendOptions::default().no_flood(),
    )
    .unwrap();
    let _ = block_on(mac.service_counter_persistence()).unwrap();

    for _ in 0..99 {
        mac.queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().no_flood(),
        )
        .unwrap();
        let _ = mac.tx_queue_mut().pop_next();
    }

    assert_eq!(
        mac.identity(local_id).unwrap().frame_counter(),
        initial_counter.wrapping_add(100)
    );
    assert_eq!(
        mac.identity(local_id).unwrap().pending_persist_target(),
        Some((initial_counter.wrapping_add(100 + 128)) & !127)
    );
}

#[test]
fn service_counter_persistence_writes_and_clears_pending_targets() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.queue_unicast(
        local_id,
        &peer_key,
        b"hello",
        &SendOptions::default().no_flood(),
    )
    .unwrap();

    let wrote = block_on(mac.service_counter_persistence()).unwrap();
    let expected_persisted = u32::from_le_bytes([7, 8, 9, 10]).wrapping_add(1 + 128) & !127;

    assert_eq!(wrote, 1);
    assert_eq!(
        mac.identity(local_id).unwrap().pending_persist_target(),
        None
    );
    assert_eq!(
        mac.identity(local_id).unwrap().persisted_counter(),
        expected_persisted
    );
    assert_eq!(mac.counter_store().stored.borrow().len(), 1);
    assert_eq!(mac.counter_store().stored.borrow()[0].1, expected_persisted);
    assert_eq!(mac.counter_store().flushes.get(), 1);
}

#[test]
fn secure_send_continues_after_future_boundary_is_persisted() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    mac.queue_unicast(
        local_id,
        &peer_key,
        b"hello",
        &SendOptions::default().no_flood(),
    )
    .unwrap();
    let _ = block_on(mac.service_counter_persistence()).unwrap();
    let persisted_boundary = mac.identity(local_id).unwrap().persisted_counter();

    for _ in 0..3 {
        mac.queue_unicast(
            local_id,
            &peer_key,
            b"again",
            &SendOptions::default().no_flood(),
        )
        .unwrap();
    }

    assert!(mac.identity(local_id).unwrap().frame_counter() < persisted_boundary);
}

#[test]
fn load_persisted_counter_aligns_to_block_boundary() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.counter_store()
        .loaded
        .borrow_mut()
        .insert(vec![0x10; 32], 255);

    let loaded = block_on(mac.load_persisted_counter(local_id)).unwrap();

    assert_eq!(loaded, 128);
    assert_eq!(mac.identity(local_id).unwrap().frame_counter(), 128);
    assert_eq!(mac.identity(local_id).unwrap().persisted_counter(), 128);
}

#[test]
fn secure_send_blocks_when_counter_window_exhausted() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.identity_mut(local_id)
        .unwrap()
        .load_persisted_counter(0);
    mac.identity_mut(local_id).unwrap().set_frame_counter(128);
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    assert_eq!(
        mac.queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().no_flood()
        ),
        Err(SendError::CounterPersistenceLag)
    );
}

#[test]
fn drain_tx_queue_transmits_all_queued_frames_in_priority_order() {
    let mut mac = make_mac();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", None, None)
        .unwrap();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Retry, b"retry", Some(SendReceipt(7)), None)
        .unwrap();
    mac.tx_queue_mut()
        .enqueue(TxPriority::ImmediateAck, b"ack", None, None)
        .unwrap();

    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

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
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", Some(SendReceipt(3)), None)
        .unwrap();

    let receipt = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();

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
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", Some(SendReceipt(3)), None)
        .unwrap();

    assert_eq!(block_on(mac.transmit_next(&mut |_, _| {})).unwrap(), None);
    assert_eq!(mac.radio().cad_calls, 1);

    assert_eq!(block_on(mac.transmit_next(&mut |_, _| {})).unwrap(), None);
    assert_eq!(mac.radio().cad_calls, 1);
    assert!(mac.radio().transmitted.is_empty());

    mac.clock().advance_ms(1_000);
    assert_eq!(
        block_on(mac.transmit_next(&mut |_, _| {})).unwrap(),
        Some(SendReceipt(3))
    );
    assert_eq!(mac.radio().cad_calls, 2);
    assert_eq!(mac.radio().transmitted.len(), 1);
}

#[test]
fn transmit_next_drops_frame_after_five_busy_cad_attempts() {
    let mut mac = make_mac();
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
    }
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", Some(SendReceipt(3)), None)
        .unwrap();

    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
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
    mac.tx_queue_mut()
        .enqueue(TxPriority::ImmediateAck, b"ack", None, None)
        .unwrap();

    let receipt = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();

    assert_eq!(receipt, None);
    assert_eq!(mac.radio().cad_calls, 0);
    assert_eq!(mac.radio().transmitted.len(), 1);
    assert_eq!(mac.radio().transmitted[0].as_slice(), b"ack");
}

#[test]
fn queue_mac_ack_builds_immediate_ack_frame() {
    let mut mac = make_mac();
    let dst = NodeHint([0x12, 0x34, 0x56]);
    let ack_tag = [0xA5; 8];

    mac.queue_mac_ack(dst, ack_tag).unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.ack_dst, Some(dst));
    assert_eq!(&queued.frame.as_slice()[header.mic_range], &ack_tag);
}

#[test]
fn queue_mac_ack_for_peer_uses_cached_source_route_when_present() {
    let mut mac = make_mac();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(
            heapless::Vec::from_slice(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])])
                .unwrap(),
        ),
    );

    mac.queue_mac_ack_for_peer(peer_id, peer_key.hint(), [0xA5; 8])
        .unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    let options = ParsedOptions::extract(queued.frame.as_slice(), header.options_range.clone()).unwrap();
    let route = options.source_route.expect("mac ack should carry a source route");
    assert_eq!(queued.frame[route].len(), 4);
}

#[test]
fn queued_mac_ack_transmits_before_application_traffic() {
    let mut mac = make_mac();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", None, None)
        .unwrap();
    mac.queue_mac_ack(NodeHint([0x55, 0x66, 0x77]), [0xCC; 8])
        .unwrap();

    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

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
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    let ack_tag = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_tag;
    let ack_dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
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
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

#[test]
fn receive_one_ignores_unmatched_mac_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    let ack_dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
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
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_some()
    );
}

#[test]
fn receive_one_emits_ack_received_for_matching_blind_unicast_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.add_channel(channel_key).unwrap();

    let receipt = mac
        .queue_blind_unicast(
            local_id,
            &peer_key,
            &channel_id,
            b"hello",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();
    let ack_tag = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_tag;
    let ack_dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
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
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

#[test]
fn receive_one_delivers_unicast_and_queues_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", true);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, b"hello".to_vec(), true)));
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.ack_dst, Some(peer_key.hint()));
}

#[test]
fn receive_one_auto_derives_registered_unicast_peer_state() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", true);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, b"hello".to_vec(), true)));
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&peer_id)
            .is_some()
    );
}

#[test]
fn receive_one_delivers_unicast_without_ack_when_not_requested() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = !packet.ack_requested();
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
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);
    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let mut deliveries = 0;
    assert!(
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Unicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );

    assert!(
        !block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Unicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );

    assert_eq!(deliveries, 1);
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_resynchronizes_peer_counter_after_out_of_window_restart() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.identity_mut(local_id)
        .unwrap()
        .peer_crypto_mut()
        .get_mut(&peer_id)
        .unwrap()
        .replay_window
        .reset(10_000, 1);

    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"hello after reboot",
        false,
        7,
    );

    assert!(!block_on(mac.receive_one(|_, _| {})).unwrap());

    let queued = mac
        .tx_queue_mut()
        .pop_next()
        .expect("counter resync should queue an echo request");
    let request_payload = decrypt_unicast_payload(queued.frame.as_slice(), &keys);
    let nonce = match request_payload.as_slice() {
        [payload_type, 4, a, b, c, d] if *payload_type == PayloadType::MacCommand as u8 => {
            u32::from_be_bytes([*a, *b, *c, *d])
        }
        other => panic!("unexpected echo request payload: {other:?}"),
    };

    let response = encode_echo_command_payload(5, &nonce.to_be_bytes());
    mac.radio_mut()
        .queue_received_unicast_with_counter(&remote, &keys, &dst_hint, &response, false, 8);

    let mut delivered = std::vec::Vec::new();
    assert!(
        block_on(mac.receive_one(|identity, event| {
            if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
                assert_eq!(identity, local_id);
                delivered.push(packet.payload_bytes().to_vec());
            }
        }))
        .unwrap()
    );
    assert_eq!(delivered.len(), 2);
    assert_eq!(delivered[0].as_slice(), response.as_slice());
    assert_eq!(delivered[1].as_slice(), b"hello after reboot");

    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"works again",
        false,
        9,
    );

    let mut delivered_again = None;
    assert!(
        block_on(mac.receive_one(|identity, event| {
            if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
                delivered_again = Some((identity, packet.payload_bytes().to_vec()));
            }
        }))
        .unwrap()
    );
    assert_eq!(delivered_again, Some((local_id, b"works again".to_vec())));
}

#[test]
fn receive_one_unicast_with_ambiguous_hint_tries_candidate_peers() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let candidate_a = PublicKey([
        0xAB, 0xAB, 0xAB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    let candidate_b = PublicKey([
        0xAB, 0xAB, 0xAB, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    let _peer_a = mac.add_peer(candidate_a).unwrap();
    let peer_b = mac.add_peer(candidate_b).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_b, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_unicast_with_source_hint(
        candidate_b.hint(),
        &keys,
        &dst_hint,
        b"hello",
        false,
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    let (identity, from, payload, ack_requested) = seen.expect("event should be delivered");
    assert_eq!(identity, local_id);
    assert!(from == candidate_a || from == candidate_b);
    assert_eq!(payload, b"hello".to_vec());
    assert!(!ack_requested);
}

#[test]
fn receive_one_full_key_unicast_does_not_auto_register_when_disabled() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let keys = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::Unicast) {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
    assert!(mac.peer_registry().lookup_by_key(&peer_key).is_none());
}

#[test]
fn receive_one_full_key_unicast_auto_registers_when_enabled() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let keys = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    mac.set_auto_register_full_key_peers(true);

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(seen, Some((local_id, peer_key, b"hello".to_vec(), false)));
    let (peer_id, _) = mac.peer_registry().lookup_by_key(&peer_key).unwrap();
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&peer_id)
            .is_some()
    );
}

#[test]
fn auto_registered_unicast_peer_does_not_displace_pinned_peer_when_registry_is_full() {
    let mut mac = make_small_peer_mac::<1>();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let pinned_key = PublicKey([0xCD; 32]);
    let _pinned_id = mac.add_peer(pinned_key).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let keys = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    mac.set_auto_register_full_key_peers(true);

    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", false);

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(!handled);
    assert!(mac.peer_registry().lookup_by_key(&pinned_key).is_some());
    assert!(mac.peer_registry().lookup_by_key(&peer_key).is_none());
}

#[test]
fn auto_registered_unicast_peer_reuses_oldest_auto_slot_when_registry_is_full() {
    let mut mac = make_small_peer_mac::<1>();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let first_remote = DummyIdentity::new([0xAB; 32]);
    let first_key = *first_remote.public_key();
    let second_remote = DummyIdentity::new([0xBC; 32]);
    let second_key = *second_remote.public_key();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    mac.set_auto_register_full_key_peers(true);

    let first_keys = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    mac.radio_mut()
        .queue_received_unicast(&first_remote, &first_keys, &dst_hint, b"first", false);
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert!(mac.peer_registry().lookup_by_key(&first_key).is_some());

    let second_keys = mac.crypto().derive_pairwise_keys(&SharedSecret([1u8; 32]));
    mac.radio_mut().queue_received_unicast(
        &second_remote,
        &second_keys,
        &dst_hint,
        b"second",
        false,
    );

    let mut seen = None;
    assert!(
        block_on(mac.receive_one(|identity, event| {
            if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
                seen = Some((identity, packet.from_key(), packet.payload_bytes().to_vec()));
            }
        }))
        .unwrap()
    );

    assert_eq!(seen, Some((local_id, Some(second_key), b"second".to_vec())));
    assert!(mac.peer_registry().lookup_by_key(&first_key).is_none());
    assert!(mac.peer_registry().lookup_by_key(&second_key).is_some());
}

#[test]
fn receive_one_hint_only_unicast_never_auto_registers_unknown_peer() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let keys = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    mac.set_auto_register_full_key_peers(true);

    mac.radio_mut().queue_received_unicast_with_source_hint(
        peer_key.hint(),
        &keys,
        &dst_hint,
        b"hello",
        false,
    );

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::Unicast) {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
    assert!(mac.peer_registry().lookup_by_key(&peer_key).is_none());
}

#[test]
fn receive_one_delivers_blind_unicast_and_queues_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone())
        .unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        true,
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::BlindUnicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen,
        Some((local_id, peer_key, channel_id, b"hello".to_vec(), true))
    );
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.ack_dst, Some(peer_key.hint()));
}

#[test]
fn receive_one_auto_derives_registered_blind_unicast_peer_state() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let pairwise = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        true,
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::BlindUnicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen,
        Some((local_id, peer_key, channel_id, b"hello".to_vec(), true))
    );
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&peer_id)
            .is_some()
    );
}

#[test]
fn receive_one_full_key_blind_unicast_auto_registers_when_enabled() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let pairwise = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.add_channel(channel_key).unwrap();
    mac.set_auto_register_full_key_peers(true);
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        false,
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::BlindUnicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen,
        Some((local_id, peer_key, channel_id, b"hello".to_vec(), false))
    );
    let (peer_id, _) = mac.peer_registry().lookup_by_key(&peer_key).unwrap();
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&peer_id)
            .is_some()
    );
}

#[test]
fn receive_one_hint_only_blind_unicast_never_auto_registers_unknown_peer() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let pairwise = mac.crypto().derive_pairwise_keys(&SharedSecret([0u8; 32]));
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.add_channel(channel_key).unwrap();
    mac.set_auto_register_full_key_peers(true);
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_blind_unicast_with_source_hint(
            peer_key.hint(),
            &pairwise,
            &channel_keys,
            &dst_hint,
            b"hello",
            false,
        );

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::BlindUnicast) {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
    assert!(mac.peer_registry().lookup_by_key(&peer_key).is_none());
}

#[test]
fn receive_one_delivers_unencrypted_blind_unicast() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone())
        .unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_unencrypted_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        false,
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::BlindUnicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen,
        Some((local_id, peer_key, channel_id, b"hello".to_vec(), false))
    );
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_delivers_source_routed_unicast_without_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let route = [RouterHint([0x44, 0x55])];

    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        true,
        7,
        None,
        None,
        Some(&route),
    );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
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
    let peer_id = mac.add_peer(peer_key).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone())
        .unwrap();

    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();
    let channel_keys = mac
        .channels()
        .lookup_by_id(&channel_id)
        .next()
        .unwrap()
        .derived
        .clone();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
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
        if let Some(packet) = received_of_type(&event, PacketType::BlindUnicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen,
        Some((local_id, peer_key, channel_id, b"hello".to_vec(), true))
    );
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn receive_one_drops_replayed_blind_unicast_after_first_delivery() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone())
        .unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        false,
    );
    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        false,
    );

    let mut deliveries = 0;
    assert!(
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::BlindUnicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );

    assert!(
        !block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::BlindUnicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );

    assert_eq!(deliveries, 1);
}

#[test]
fn receive_one_blind_unicast_with_ambiguous_hint_tries_candidate_peers() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let candidate_a = PublicKey([
        0xAB, 0xAB, 0xAB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    let candidate_b = PublicKey([
        0xAB, 0xAB, 0xAB, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    let _peer_a = mac.add_peer(candidate_a).unwrap();
    let peer_b = mac.add_peer(candidate_b).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    let channel_id = channel_keys.channel_id;
    mac.install_pairwise_keys(local_id, peer_b, pairwise.clone())
        .unwrap();
    mac.add_channel(channel_key).unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut()
        .queue_received_blind_unicast_with_source_hint(
            candidate_b.hint(),
            &pairwise,
            &channel_keys,
            &dst_hint,
            b"hello",
            false,
        );

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::BlindUnicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    let (identity, from, seen_channel_id, payload, ack_requested) =
        seen.expect("event should be delivered");
    assert_eq!(identity, local_id);
    assert!(from == candidate_a || from == candidate_b);
    assert_eq!(seen_channel_id, channel_id);
    assert_eq!(payload, b"hello".to_vec());
    assert!(!ack_requested);
}

#[test]
fn receive_one_repeater_forwards_blind_unicast_using_original_encrypted_frame() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let pairwise = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();
    let channel_keys = mac
        .channels()
        .lookup_by_id(&channel_id)
        .next()
        .unwrap()
        .derived
        .clone();
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
        &forwarded.frame.as_slice()
            [forwarded_header.body_range.start - 8..forwarded_header.body_range.start],
        &original.as_slice()
            [original_header.body_range.start - 8..original_header.body_range.start],
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
    mac.add_peer(peer_key).unwrap();
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut seen =
        heapless::Vec::<(LocalIdentityId, PublicKey, ChannelId, std::vec::Vec<u8>), 4>::new();
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Multicast) {
            seen.push((
                identity,
                packet.from_key().unwrap(),
                packet.channel().unwrap().id,
                packet.payload_bytes().to_vec(),
            ))
            .unwrap();
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
    mac.add_peer(peer_key).unwrap();
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &keys, b"group");
    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut deliveries = 0;
    assert!(
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Multicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );

    assert!(
        !block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Multicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );

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
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    mac.add_peer(peer_key).unwrap();
    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut seen = false;
    let handled = block_on(mac.receive_one(|_, event| {
        if is_received_type(&event, PacketType::Multicast) {
            seen = true;
        }
    }))
    .unwrap();

    assert!(!handled);
    assert!(!seen);
}

#[test]
fn receive_one_multicast_with_full_registry_still_delivers_unknown_sender() {
    let mut mac = make_small_peer_mac::<1>();
    let _local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let known_peer = PublicKey([0xCD; 32]);
    let _peer_id = mac.add_peer(known_peer).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &keys, b"group");

    let mut seen = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Multicast) {
            seen = Some((
                identity,
                packet.from_key(),
                packet.from_hint(),
                packet.payload_bytes().to_vec(),
            ));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(
        seen,
        Some((
            LocalIdentityId(0),
            Some(*remote.public_key()),
            Some(remote.public_key().hint()),
            b"group".to_vec(),
        ))
    );
    assert_eq!(
        mac.peer_registry().get(PeerId(0)).unwrap().public_key,
        known_peer
    );
}

#[test]
fn receive_one_learns_trace_route_as_return_source_route_for_unicast_sender() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let trace = [RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])];

    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        false,
        7,
        None,
        Some(&trace),
        None,
    );

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Source(
            heapless::Vec::from_slice(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])])
                .unwrap()
        ))
    );
}

#[test]
fn send_unicast_uses_cached_source_route_when_present() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
    let trace = [RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])];

    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        false,
        7,
        None,
        Some(&trace),
        None,
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let options = SendOptions::default();
    let _ = block_on(mac.send_unicast(local_id, &peer_key, b"reply", &options)).unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    let mut source_route = std::vec::Vec::<[u8; 2]>::new();
    for entry in iter_options(queued.frame.as_slice(), header.options_range.clone()) {
        let (number, value) = entry.unwrap();
        if OptionNumber::from(number) != OptionNumber::SourceRoute {
            continue;
        }
        for chunk in value.chunks_exact(2) {
            source_route.push([chunk[0], chunk[1]]);
        }
    }

    assert_eq!(source_route.as_slice(), &[[0x01, 0x02], [0x03, 0x04]]);
}

#[test]
fn receive_one_learns_flood_hops_for_multicast_sender() {
    let mut mac = make_mac();
    let _local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    mac.radio_mut().queue_received_multicast_with_flood(
        &remote,
        channel_id,
        &keys,
        b"group",
        Some((4, 2)),
    );

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
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

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
    let original_frame = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    let forwarded_frame = rewrite_forwarded_fixture(original_frame.as_slice());
    mac.radio_mut()
        .queue_received_frame(forwarded_frame.as_slice());

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert_eq!(pending.state, AckState::AwaitingAck);
}

#[test]
fn receive_one_repeater_forwards_source_routed_unicast_and_rewrites_options() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    let dst = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    let trace = [RouterHint([0x33, 0x44])];
    let source_route = [repeater_hint, RouterHint([0x21, 0x22])];

    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst,
        b"hello",
        false,
        7,
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

    assert_eq!(
        seen_trace,
        Some([repeater_hint.0.as_slice(), trace[0].0.as_slice()].concat())
    );
    assert_eq!(seen_source_route, Some(source_route[1].0.to_vec()));
}

#[test]
fn receive_one_repeater_forwards_source_routed_unicast_without_trace_route() {
    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    let repeater_id = repeater.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = repeater
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let mut destination = make_mac();
    let destination_identity = DummyIdentity::new([0x20; 32]);
    let dst_hint = destination_identity.public_key().hint();
    let destination_id = destination.add_identity(destination_identity).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = destination.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    destination
        .install_pairwise_keys(destination_id, peer_id, keys.clone())
        .unwrap();

    let source_route = [repeater_hint];

    repeater.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"pfs-request-like-payload",
        true,
        7,
        Some((5, 0)),
        None,
        Some(&source_route),
    );

    let handled = block_on(repeater.receive_one(|_, _| {})).unwrap();
    assert!(handled);

    let forwarded = repeater.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let options = ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone())
        .unwrap();
    assert!(options.trace_route.is_none());
    assert!(
        options.source_route.is_some(),
        "final forwarded frame should preserve an empty source-route option: {:?}",
        options.source_route
    );
    let source_route_range = options.source_route.unwrap();
    assert_eq!(
        forwarded.frame[source_route_range].len(),
        0,
        "final forwarded frame should preserve source-route provenance with zero remaining hops"
    );

    destination
        .radio_mut()
        .queue_received_frame(forwarded.frame.as_slice());

    let mut seen = None;
    let delivered = block_on(destination.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
        }
    }))
    .unwrap();

    assert!(delivered);
    assert_eq!(
        seen,
        Some((
            destination_id,
            peer_key,
            b"pfs-request-like-payload".to_vec(),
            true,
        ))
    );
}

#[test]
fn receive_one_repeater_forwards_source_routed_mac_ack() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let mut buf = [0u8; 256];
    let frame = PacketBuilder::new(&mut buf)
        .mac_ack(NodeHint([0x77, 0x66, 0x55]), [0xA5; 8])
        .option(OptionNumber::TraceRoute, &[0x33, 0x44])
        .source_route(&[repeater_hint, RouterHint([0x21, 0x22])])
        .build()
        .unwrap();

    mac.radio_mut().queue_received_frame(frame);

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(handled);

    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    assert_eq!(header.packet_type(), PacketType::MacAck);
    let options = ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone())
        .unwrap();
    let source_route = options
        .source_route
        .expect("forwarded MAC ACK should keep the remaining source route");
    assert_eq!(forwarded.frame[source_route].len(), 2);
}

#[test]
fn receive_one_repeater_flood_forwards_with_delay_and_decrements_hops() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.add_channel(channel_key).unwrap();

    mac.radio_mut().queue_received_multicast_with_flood(
        &remote,
        channel_id,
        &keys,
        b"group",
        Some((4, 2)),
    );

    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert_eq!(mac.dup_cache().len(), 1);
    assert_eq!(mac.tx_queue().len(), 1);
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(forwarded.priority, TxPriority::Forward);
    assert!(forwarded.not_before_ms >= 123);
    assert!(forwarded.not_before_ms <= 323);
    assert_eq!(forwarded.forward_deferrals, 0);

    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    assert_eq!(header.flood_hops.unwrap(), FloodHops::new(3, 3).unwrap());
}

#[test]
fn receive_one_defers_pending_forward_when_duplicate_is_overheard() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
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
    assert_eq!(mac.tx_queue().len(), 1);
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(forwarded.priority, TxPriority::Forward);
    assert_eq!(forwarded.forward_deferrals, 1);
}

#[test]
fn receive_one_drops_pending_forward_after_max_duplicate_deferrals() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
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

    for _ in 0..mac.repeater_config().flood_contention_max_deferrals {
        mac.radio_mut().queue_received_frame(frame.as_slice());
        let handled = block_on(mac.receive_one(|_, _| {})).unwrap();
        assert!(!handled);
        assert_eq!(mac.tx_queue().len(), 1);
    }

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
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let route = [RouterHint([1, 2])];
    let options = SendOptions::default()
        .with_ack_requested(true)
        .try_with_source_route(&route)
        .unwrap();
    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"later", None, None)
        .unwrap();

    block_on(mac.poll_cycle(|_, _| {})).unwrap();

    assert_eq!(mac.radio().transmitted.len(), 1);
    assert_eq!(mac.tx_queue().len(), 1);
    assert_eq!(
        mac.tx_queue_mut().pop_next().unwrap().frame.as_slice(),
        b"later"
    );
    assert!(matches!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .unwrap()
            .state,
        AckState::AwaitingForward { .. }
    ));
}

#[test]
fn drain_tx_queue_returns_when_cad_keeps_reporting_busy() {
    let mut mac = make_mac();
    mac.radio_mut().cad_responses.push_back(true).unwrap();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", None, None)
        .unwrap();

    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    assert!(mac.radio().transmitted.is_empty());
    assert_eq!(mac.radio().cad_calls, 1);
}

#[test]
fn modeled_network_delivers_after_airtime_and_link_delay() {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    let mut alice = network.add_radio_with_config(256, 100);
    let mut bob = network.add_radio_with_config(256, 100);
    network.set_link_profile(
        alice.id(),
        bob.id(),
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -72,
            base_snr: Snr::from_decibels(6),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 25,
            drop_per_thousand: 0,
        },
    );

    block_on(alice.transmit(b"hello", TxOptions::default())).unwrap();

    let mut buf = [0u8; 16];
    assert!(matches!(poll_radio_once(&mut bob, &mut buf), Poll::Pending));

    network.advance_ms(124);
    assert!(matches!(poll_radio_once(&mut bob, &mut buf), Poll::Pending));

    network.advance_ms(1);
    let rx = match poll_radio_once(&mut bob, &mut buf) {
        Poll::Ready(Ok(rx)) => rx,
        Poll::Ready(Err(())) => panic!("expected successful delivery"),
        Poll::Pending => panic!("expected ready delivery"),
    };
    assert_eq!(rx.len, 5);
    assert_eq!(&buf[..rx.len], b"hello");
    assert_eq!(rx.rssi, -72);
    assert_eq!(rx.snr, Snr::from_decibels(6));
}

#[test]
fn modeled_network_reports_cad_busy_during_active_transmission() {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock);
    let mut alice = network.add_radio_with_config(256, 100);
    let mut bob = network.add_radio_with_config(256, 100);
    network.connect_bidirectional(alice.id(), bob.id());

    block_on(alice.transmit(b"hello", TxOptions::default())).unwrap();
    let result = block_on(bob.transmit(
        b"retry",
        TxOptions {
            cad_timeout_ms: Some(0),
        },
    ));
    assert!(matches!(result, Err(TxError::CadTimeout)));
}

#[test]
fn modeled_network_drops_colliding_frames_and_respects_packet_loss() {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    network.reseed(1);
    let mut alice = network.add_radio_with_config(256, 100);
    let mut bob = network.add_radio_with_config(256, 100);
    let mut carol = network.add_radio_with_config(256, 100);
    network.connect(alice.id(), carol.id());
    network.connect(bob.id(), carol.id());

    block_on(alice.transmit(b"from-alice", TxOptions::default())).unwrap();
    block_on(bob.transmit(b"from-bob", TxOptions::default())).unwrap();

    network.advance_ms(100);
    let mut buf = [0u8; 32];
    assert!(matches!(poll_radio_once(&mut carol, &mut buf), Poll::Pending));

    let mut dave = network.add_radio_with_config(256, 100);
    network.set_link_profile(
        alice.id(),
        dave.id(),
        crate::test_support::ModeledLinkProfile {
            connected: true,
            drop_per_thousand: 1000,
            ..crate::test_support::ModeledLinkProfile::connected()
        },
    );
    block_on(alice.transmit(b"lost", TxOptions::default())).unwrap();
    network.advance_ms(100);
    assert!(matches!(poll_radio_once(&mut dave, &mut buf), Poll::Pending));
}

#[test]
fn modeled_seven_hop_line_learns_and_uses_source_routes_end_to_end() {
    let mut scenario = build_modeled_line_scenario(8);
    install_endpoint_pairwise_keys(&mut scenario);

    let alice = 0usize;
    let bob = scenario.keys.len() - 1;
    let route_hops = u8::try_from(bob - alice).unwrap();
    let first_receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"hello-7hop",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(route_hops)
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };

    let bob_first_delivery = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        800,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"hello-7hop" {
                bob_first_delivery.set(bob_first_delivery.get() + 1);
            }
        },
        || {
            bob_first_delivery.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&first_receipt)
                    .is_none()
        },
        "bob should receive the initial flooded hello across seven hops",
    );

    let (alice_peer_id, _) = scenario.macs[bob]
        .borrow()
        .peer_registry()
        .lookup_by_key(&scenario.keys[alice])
        .unwrap();
    let learned_route_to_alice = scenario.macs[bob]
        .borrow()
        .peer_registry()
        .get(alice_peer_id)
        .unwrap()
        .route
        .clone();
    assert!(matches!(
        learned_route_to_alice,
        Some(CachedRoute::Source(route)) if route.len() == 6
    ));

    let reply_receipt = {
        let mut bob_mac = scenario.macs[bob].borrow_mut();
        bob_mac
            .queue_unicast(
                scenario.identity_ids[bob],
                &scenario.keys[alice],
                b"reply-7hop",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .no_flood()
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let alice_reply_delivery = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        800,
        |node_index, _, event| {
            if node_index != alice {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"reply-7hop" {
                alice_reply_delivery.set(alice_reply_delivery.get() + 1);
            }
        },
        || {
            alice_reply_delivery.get() == 1
                && scenario.macs[bob]
                    .borrow()
                    .identity(scenario.identity_ids[bob])
                    .unwrap()
                    .pending_ack(&reply_receipt)
                    .is_none()
        },
        "alice should receive bob's source-routed reply across seven hops",
    );

    let (bob_peer_id, _) = scenario.macs[alice]
        .borrow()
        .peer_registry()
        .lookup_by_key(&scenario.keys[bob])
        .unwrap();
    let learned_route_to_bob = scenario.macs[alice]
        .borrow()
        .peer_registry()
        .get(bob_peer_id)
        .unwrap()
        .route
        .clone();
    assert!(matches!(
        learned_route_to_bob,
        Some(CachedRoute::Source(route)) if route.len() == 6
    ));

    let midpoint = 3usize;
    let alice_broadcast_delivery = Cell::new(0usize);
    let bob_broadcast_delivery = Cell::new(0usize);
    {
        let mut midpoint_mac = scenario.macs[midpoint].borrow_mut();
        midpoint_mac
            .queue_broadcast(
                scenario.identity_ids[midpoint],
                b"mid-broadcast",
                &SendOptions::default().unencrypted().with_flood_hops(4),
            )
            .unwrap();
    }
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        800,
        |node_index, _, event| {
            let Some(packet) = received_of_type(event, PacketType::Broadcast) else {
                return;
            };
            if packet.payload_bytes() != b"mid-broadcast" {
                return;
            }
            if node_index == alice {
                alice_broadcast_delivery.set(alice_broadcast_delivery.get() + 1);
            }
            if node_index == bob {
                bob_broadcast_delivery.set(bob_broadcast_delivery.get() + 1);
            }
        },
        || alice_broadcast_delivery.get() == 1 && bob_broadcast_delivery.get() == 1,
        "a midpoint broadcast should coexist with learned-route traffic across the line",
    );

    let follow_up_receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"follow-up-7hop",
                &SendOptions::default().with_ack_requested(true).no_flood(),
            )
            .unwrap()
            .unwrap()
    };
    let bob_follow_up_delivery = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        800,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"follow-up-7hop" {
                bob_follow_up_delivery.set(bob_follow_up_delivery.get() + 1);
            }
        },
        || {
            bob_follow_up_delivery.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&follow_up_receipt)
                    .is_none()
        },
        "bob should receive alice's cached-route follow-up without flood routing",
    );
}

#[test]
fn modeled_route_retry_recovers_after_mid_route_break_via_alternate_repeaters() {
    let mut scenario = build_modeled_line_scenario(10);
    let alice = 0usize;
    let bob = 7usize;
    let alt_a = 8usize;
    let alt_b = 9usize;
    let direct_left = 3usize;
    let direct_right = 4usize;
    install_pairwise_keys_between(&mut scenario, alice, bob);

    let bob_prime_delivery = Cell::new(0usize);
    {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"prime-route",
                &SendOptions::default()
                    .with_flood_hops(8)
                    .with_trace_route(),
            )
            .unwrap();
    }
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        1000,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"prime-route" {
                bob_prime_delivery.set(bob_prime_delivery.get() + 1);
            }
        },
        || bob_prime_delivery.get() == 1,
        "bob should receive the initial route-discovery packet",
    );

    let alice_prime_reply_delivery = Cell::new(0usize);
    {
        let mut bob_mac = scenario.macs[bob].borrow_mut();
        bob_mac
            .queue_unicast(
                scenario.identity_ids[bob],
                &scenario.keys[alice],
                b"prime-reply",
                &SendOptions::default().no_flood().with_trace_route(),
            )
            .unwrap();
    }
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        1000,
        |node_index, _, event| {
            if node_index != alice {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"prime-reply" {
                alice_prime_reply_delivery.set(alice_prime_reply_delivery.get() + 1);
            }
        },
        || alice_prime_reply_delivery.get() == 1,
        "alice should receive the priming reply over the learned source route",
    );

    disconnect_modeled_bidirectional(
        &scenario.network,
        scenario.radio_ids[direct_left],
        scenario.radio_ids[direct_right],
    );
    connect_modeled_bidirectional(
        &scenario.network,
        scenario.radio_ids[direct_left],
        scenario.radio_ids[alt_a],
    );
    connect_modeled_bidirectional(
        &scenario.network,
        scenario.radio_ids[alt_a],
        scenario.radio_ids[alt_b],
    );
    connect_modeled_bidirectional(
        &scenario.network,
        scenario.radio_ids[alt_b],
        scenario.radio_ids[direct_right],
    );

    let route_retry_seen = Cell::new(false);
    let ack_timeout_seen = Cell::new(false);
    let bob_recovered_delivery = Cell::new(0usize);
    let receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"recover-via-route-retry",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(8),
            )
            .unwrap()
            .unwrap()
    };
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        2400,
        |node_index, identity_id, event| {
            if node_index == bob {
                if let Some(packet) = received_of_type(event, PacketType::Unicast) {
                    if packet.payload_bytes() == b"recover-via-route-retry" {
                        bob_recovered_delivery.set(bob_recovered_delivery.get() + 1);
                        if packet.options().route_retry {
                            route_retry_seen.set(true);
                        }
                    }
                }
            }
            if node_index == alice {
                if let MacEventRef::AckTimeout { receipt: timed_out, .. } = event {
                    if identity_id == scenario.identity_ids[alice] && *timed_out == receipt {
                        ack_timeout_seen.set(true);
                    }
                }
            }
        },
        || {
            bob_recovered_delivery.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&receipt)
                    .is_none()
        },
        "route retry should recover delivery over the alternate repeater branch",
    );

    assert!(route_retry_seen.get());
    assert!(!ack_timeout_seen.get());
    assert_eq!(bob_recovered_delivery.get(), 1);
}

#[test]
fn modeled_parallel_paths_prefer_stronger_branch_for_route_learning() {
    // Diamond topology:
    // Alice -> strong -> Bob
    // Alice -> weak   -> Bob
    //
    // The initial flooded packet should still arrive either way, but the trace
    // route Bob learns back to Alice should prefer the stronger branch.
    let mut scenario = build_modeled_line_scenario(4);
    let alice = 0usize;
    let strong = 1usize;
    let weak = 2usize;
    let bob = 3usize;
    install_pairwise_keys_between(&mut scenario, alice, bob);

    disconnect_modeled_bidirectional(
        &scenario.network,
        scenario.radio_ids[strong],
        scenario.radio_ids[weak],
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[alice],
        scenario.radio_ids[strong],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -60,
            base_snr: Snr::from_decibels(14),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[strong],
        scenario.radio_ids[bob],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -61,
            base_snr: Snr::from_decibels(12),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[alice],
        scenario.radio_ids[weak],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -84,
            base_snr: Snr::from_decibels(1),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 6,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[weak],
        scenario.radio_ids[bob],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -84,
            base_snr: Snr::from_decibels(1),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 6,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[strong],
        scenario.radio_ids[weak],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -58,
            base_snr: Snr::from_decibels(16),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 1,
            drop_per_thousand: 0,
        },
    );

    let receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"parallel-paths",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(3)
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let delivered = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        600,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"parallel-paths" {
                delivered.set(delivered.get() + 1);
            }
        },
        || {
            delivered.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&receipt)
                    .is_none()
        },
        "bob should receive the initial packet across the stronger branch",
    );

    let (alice_peer_id, _) = scenario.macs[bob]
        .borrow()
        .peer_registry()
        .lookup_by_key(&scenario.keys[alice])
        .unwrap();
    let learned_route = scenario.macs[bob]
        .borrow()
        .peer_registry()
        .get(alice_peer_id)
        .unwrap()
        .route
        .clone();
    let strong_hint = scenario.macs[strong]
        .borrow()
        .identity(scenario.identity_ids[strong])
        .unwrap()
        .identity()
        .public_key()
        .router_hint();
    assert_eq!(
        learned_route,
        Some(CachedRoute::Source(heapless::Vec::from_slice(&[strong_hint]).unwrap()))
    );
}

#[test]
fn modeled_asymmetric_links_still_support_bidirectional_exchange() {
    // Same four-node line, but each hop has noticeably different forward and
    // reverse quality. This checks that the mesh does not silently assume
    // symmetric link quality.
    let mut scenario = build_modeled_line_scenario(4);
    let alice = 0usize;
    let bob = 3usize;
    install_pairwise_keys_between(&mut scenario, alice, bob);

    scenario.network.set_link_profile(
        scenario.radio_ids[0],
        scenario.radio_ids[1],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -62,
            base_snr: Snr::from_decibels(12),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    scenario.network.set_link_profile(
        scenario.radio_ids[1],
        scenario.radio_ids[0],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -83,
            base_snr: Snr::from_decibels(1),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 5,
            drop_per_thousand: 0,
        },
    );
    scenario.network.set_link_profile(
        scenario.radio_ids[1],
        scenario.radio_ids[2],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -66,
            base_snr: Snr::from_decibels(8),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 3,
            drop_per_thousand: 0,
        },
    );
    scenario.network.set_link_profile(
        scenario.radio_ids[2],
        scenario.radio_ids[1],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -81,
            base_snr: Snr::from_decibels(2),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 6,
            drop_per_thousand: 0,
        },
    );
    scenario.network.set_link_profile(
        scenario.radio_ids[2],
        scenario.radio_ids[3],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -64,
            base_snr: Snr::from_decibels(10),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    scenario.network.set_link_profile(
        scenario.radio_ids[3],
        scenario.radio_ids[2],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -85,
            base_snr: Snr::from_decibels(0),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 6,
            drop_per_thousand: 0,
        },
    );

    let first_receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"asymmetric-forward",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(4)
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let bob_first = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        900,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"asymmetric-forward" {
                bob_first.set(bob_first.get() + 1);
            }
        },
        || {
            bob_first.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&first_receipt)
                    .is_none()
        },
        "alice should still complete an acked exchange over asymmetric links",
    );

    let reply_receipt = {
        let mut bob_mac = scenario.macs[bob].borrow_mut();
        bob_mac
            .queue_unicast(
                scenario.identity_ids[bob],
                &scenario.keys[alice],
                b"asymmetric-reply",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .no_flood()
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let alice_reply = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        900,
        |node_index, _, event| {
            if node_index != alice {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"asymmetric-reply" {
                alice_reply.set(alice_reply.get() + 1);
            }
        },
        || {
            alice_reply.get() == 1
                && scenario.macs[bob]
                    .borrow()
                    .identity(scenario.identity_ids[bob])
                    .unwrap()
                    .pending_ack(&reply_receipt)
                    .is_none()
        },
        "bob should also complete the reverse acked exchange over the same asymmetric line",
    );
}

#[test]
fn modeled_dense_repeater_neighborhood_prefers_one_of_the_best_candidates() {
    // Alice and Bob have four candidate relays between them. Two are strong and
    // two are weak. Flood learning should settle on one of the stronger relays.
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    let mut macs = Vec::new();
    let mut identity_ids = Vec::new();
    let mut keys = Vec::new();
    let mut radio_ids = Vec::new();
    for index in 0..6 {
        let radio = network.add_radio_with_config(256, 50);
        radio_ids.push(radio.id());
        let mut mac = crate::test_support::make_modeled_test_mac(radio, clock.clone());
        mac.repeater_config_mut().enabled = (1..=4).contains(&index);
        let id = mac
            .add_identity(crate::test_support::DummyIdentity::new([
                0x30u8.wrapping_add(index as u8);
                32
            ]))
            .unwrap();
        identity_ids.push(id);
        keys.push(*mac.identity(id).unwrap().identity().public_key());
        macs.push(RefCell::new(mac));
    }

    for repeater in 1..=4 {
        let profile = if repeater <= 2 {
            crate::test_support::ModeledLinkProfile {
                connected: true,
                base_rssi: -61,
                base_snr: Snr::from_decibels(12),
                rssi_jitter_dbm: 0,
                snr_jitter_centibels: 0,
                propagation_delay_ms: 2,
                drop_per_thousand: 0,
            }
        } else {
            crate::test_support::ModeledLinkProfile {
                connected: true,
                base_rssi: -82,
                base_snr: Snr::from_decibels(1),
                rssi_jitter_dbm: 0,
                snr_jitter_centibels: 0,
                propagation_delay_ms: 6,
                drop_per_thousand: 0,
            }
        };
        connect_modeled_bidirectional_with_profile(&network, radio_ids[0], radio_ids[repeater], profile);
        connect_modeled_bidirectional_with_profile(&network, radio_ids[repeater], radio_ids[5], profile);
    }
    for left in 1..=4 {
        for right in (left + 1)..=4 {
            connect_modeled_bidirectional_with_profile(
                &network,
                radio_ids[left],
                radio_ids[right],
                crate::test_support::ModeledLinkProfile {
                    connected: true,
                    base_rssi: -57,
                    base_snr: Snr::from_decibels(15),
                    rssi_jitter_dbm: 0,
                    snr_jitter_centibels: 0,
                    propagation_delay_ms: 1,
                    drop_per_thousand: 0,
                },
            );
        }
    }

    let pairwise = PairwiseKeys {
        k_enc: [0x21; 16],
        k_mic: [0x42; 16],
    };
    {
        let mut alice_mac = macs[0].borrow_mut();
        let peer_id = alice_mac.add_peer(keys[5]).unwrap();
        alice_mac.install_pairwise_keys(identity_ids[0], peer_id, pairwise.clone()).unwrap();
    }
    {
        let mut bob_mac = macs[5].borrow_mut();
        let peer_id = bob_mac.add_peer(keys[0]).unwrap();
        bob_mac.install_pairwise_keys(identity_ids[5], peer_id, pairwise).unwrap();
    }

    let receipt = {
        let mut alice_mac = macs[0].borrow_mut();
        alice_mac
            .queue_unicast(
                identity_ids[0],
                &keys[5],
                b"dense-neighborhood",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(3)
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let bob_delivery = Cell::new(0usize);
    pump_modeled_until(
        &network,
        &macs,
        25,
        700,
        |node_index, _, event| {
            if node_index != 5 {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"dense-neighborhood" {
                bob_delivery.set(bob_delivery.get() + 1);
            }
        },
        || {
            bob_delivery.get() == 1
                && macs[0]
                    .borrow()
                    .identity(identity_ids[0])
                    .unwrap()
                    .pending_ack(&receipt)
                    .is_none()
        },
        "one of the stronger candidate repeaters should carry the first route-learning packet",
    );

    let (alice_peer_id, _) = macs[5].borrow().peer_registry().lookup_by_key(&keys[0]).unwrap();
    let learned_route = macs[5]
        .borrow()
        .peer_registry()
        .get(alice_peer_id)
        .unwrap()
        .route
        .clone();
    let strong_hints = [
        macs[1].borrow().identity(identity_ids[1]).unwrap().identity().public_key().router_hint(),
        macs[2].borrow().identity(identity_ids[2]).unwrap().identity().public_key().router_hint(),
    ];
    assert!(matches!(
        learned_route,
        Some(CachedRoute::Source(route))
            if route.len() == 1 && strong_hints.contains(&route[0])
    ));
}

#[test]
fn modeled_unknown_multicast_senders_deliver_unique_messages_without_peer_registry_entries() {
    // Two senders share a channel with a receiver across repeaters, but the
    // receiver never registers them as peers. Group delivery should still work.
    let mut scenario = build_modeled_line_scenario(4);
    let sender_a = 0usize;
    let sender_b = 1usize;
    let receiver = 3usize;
    let channel_id = install_channel_on_all(&mut scenario, ChannelKey([0x7B; 32]));

    {
        let mut sender_mac = scenario.macs[sender_a].borrow_mut();
        sender_mac
            .queue_multicast(
                scenario.identity_ids[sender_a],
                &channel_id,
                b"group-from-a",
                &SendOptions::default(),
            )
            .unwrap();
    }
    {
        let mut sender_mac = scenario.macs[sender_b].borrow_mut();
        sender_mac
            .queue_multicast(
                scenario.identity_ids[sender_b],
                &channel_id,
                b"group-from-b",
                &SendOptions::default(),
            )
            .unwrap();
    }

    let seen = RefCell::new(std::collections::BTreeSet::new());
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        700,
        |node_index, _, event| {
            if node_index != receiver {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Multicast) else {
                return;
            };
            seen.borrow_mut().insert((
                packet.from_hint().expect("multicast source hint should be present").0,
                packet.payload_bytes().to_vec(),
            ));
        },
        || seen.borrow().len() == 2,
        "receiver should accept multicast from unknown senders without peer registration",
    );
    assert!(scenario.macs[receiver]
        .borrow()
        .peer_registry()
        .lookup_by_key(&scenario.keys[sender_a])
        .is_none());
    assert!(scenario.macs[receiver]
        .borrow()
        .peer_registry()
        .lookup_by_key(&scenario.keys[sender_b])
        .is_none());
}

#[test]
fn modeled_multihop_counter_resync_routes_echo_request_and_response() {
    // Alice and Bob first learn routes in both directions. Alice then
    // "restarts" by rewinding its local frame counter and sending another
    // multi-hop packet. Bob should respond by issuing a routed Echo Request,
    // and Alice should answer with a routed Echo Response. The direct
    // deferred-packet replay behavior is covered in
    // `receive_one_resynchronizes_peer_counter_after_out_of_window_restart`.
    let mut scenario = build_modeled_line_scenario(6);
    let alice = 0usize;
    let bob = 5usize;
    install_pairwise_keys_between(&mut scenario, alice, bob);

    let prime_receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"prime-counter-route",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(6)
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let bob_prime = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        900,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"prime-counter-route" {
                bob_prime.set(bob_prime.get() + 1);
            }
        },
        || {
            bob_prime.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&prime_receipt)
                    .is_none()
        },
        "the priming packet should establish the route before the restart simulation",
    );

    let prime_reply_receipt = {
        let mut bob_mac = scenario.macs[bob].borrow_mut();
        bob_mac
            .queue_unicast(
                scenario.identity_ids[bob],
                &scenario.keys[alice],
                b"prime-counter-reply",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .no_flood()
                    .with_trace_route(),
            )
            .unwrap()
            .unwrap()
    };
    let alice_prime_reply = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        900,
        |node_index, _, event| {
            if node_index != alice {
                return;
            }
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            if packet.payload_bytes() == b"prime-counter-reply" {
                alice_prime_reply.set(alice_prime_reply.get() + 1);
            }
        },
        || {
            alice_prime_reply.get() == 1
                && scenario.macs[bob]
                    .borrow()
                    .identity(scenario.identity_ids[bob])
                    .unwrap()
                    .pending_ack(&prime_reply_receipt)
                    .is_none()
        },
        "the reply should teach alice a cached route back to bob before the restart simulation",
    );

    scenario.macs[alice]
        .borrow_mut()
        .identity_mut(scenario.identity_ids[alice])
        .unwrap()
        .load_persisted_counter(0);
    scenario.macs[alice]
        .borrow_mut()
        .identity_mut(scenario.identity_ids[alice])
        .unwrap()
        .set_frame_counter(1);

    {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"after-restart",
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(6),
            )
            .unwrap();
    };
    let alice_echo_requests = Cell::new(0usize);
    let bob_echo_responses = Cell::new(0usize);
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        1400,
        |node_index, _, event| {
            let Some(packet) = received_of_type(event, PacketType::Unicast) else {
                return;
            };
            match packet.payload_bytes() {
                [payload_type, 4, ..] if node_index == alice && *payload_type == PayloadType::MacCommand as u8 => {
                    alice_echo_requests.set(alice_echo_requests.get() + 1);
                }
                [payload_type, 5, ..] if node_index == bob && *payload_type == PayloadType::MacCommand as u8 => {
                    bob_echo_responses.set(bob_echo_responses.get() + 1);
                }
                _ => {}
            }
        },
        || alice_echo_requests.get() >= 1 && bob_echo_responses.get() >= 1,
        "the multi-hop resync exchange should carry both the Echo Request and the Echo Response",
    );
}

#[test]
fn modeled_mixed_packet_classes_coexist_on_the_same_mesh() {
    // Exercise several packet classes on the same four-node line without
    // changing topology or installed state between phases. Staging the sends
    // keeps the assertions easy to read while still proving that the classes
    // can coexist in one mesh.
    let mut scenario = build_modeled_line_scenario(4);
    let alice = 0usize;
    let bob = 3usize;
    install_pairwise_keys_between(&mut scenario, alice, bob);
    let channel_id = install_channel_on_all(&mut scenario, ChannelKey([0x66; 32]));

    let bob_unicast = Cell::new(0usize);
    let unicast_receipt = {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_unicast(
                scenario.identity_ids[alice],
                &scenario.keys[bob],
                b"mixed-unicast",
                &SendOptions::default().with_ack_requested(true).with_flood_hops(4),
            )
            .unwrap()
            .unwrap()
    };
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        900,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            if let Some(packet) = received_of_type(event, PacketType::Unicast) {
                if packet.payload_bytes() == b"mixed-unicast" {
                    bob_unicast.set(bob_unicast.get() + 1);
                }
            }
        },
        || {
            bob_unicast.get() == 1
                && scenario.macs[alice]
                    .borrow()
                    .identity(scenario.identity_ids[alice])
                    .unwrap()
                    .pending_ack(&unicast_receipt)
                    .is_none()
        },
        "the unicast phase should complete normally",
    );

    let bob_multicast = Cell::new(0usize);
    {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        alice_mac
            .queue_multicast(
                scenario.identity_ids[alice],
                &channel_id,
                b"mixed-multicast",
                &SendOptions::default(),
            )
            .unwrap();
    }
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        700,
        |node_index, _, event| {
            if node_index != bob {
                return;
            }
            if let Some(packet) = received_of_type(event, PacketType::Multicast) {
                if packet.payload_bytes() == b"mixed-multicast" {
                    bob_multicast.set(bob_multicast.get() + 1);
                }
            }
        },
        || bob_multicast.get() == 1,
        "the multicast phase should still work on the same mesh",
    );

    let alice_blind = Cell::new(0usize);
    let blind_receipt = {
        let mut bob_mac = scenario.macs[bob].borrow_mut();
        bob_mac
            .queue_blind_unicast(
                scenario.identity_ids[bob],
                &scenario.keys[alice],
                &channel_id,
                b"mixed-blind",
                &SendOptions::default().with_ack_requested(true).with_flood_hops(4),
            )
            .unwrap()
            .unwrap()
    };
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        900,
        |node_index, _, event| {
            if node_index != alice {
                return;
            }
            if let Some(packet) = received_of_type(event, PacketType::BlindUnicast) {
                if packet.payload_bytes() == b"mixed-blind" {
                    alice_blind.set(alice_blind.get() + 1);
                }
            }
        },
        || {
            alice_blind.get() == 1
                && scenario.macs[bob]
                    .borrow()
                    .identity(scenario.identity_ids[bob])
                    .unwrap()
                    .pending_ack(&blind_receipt)
                    .is_none()
        },
        "the blind-unicast phase should also complete on the same mesh",
    );

    let alice_broadcast = Cell::new(0usize);
    let bob_broadcast = Cell::new(0usize);
    {
        let mut midpoint_mac = scenario.macs[1].borrow_mut();
        midpoint_mac
            .queue_broadcast(
                scenario.identity_ids[1],
                b"mixed-broadcast",
                &SendOptions::default().unencrypted().with_flood_hops(4),
            )
            .unwrap();
    }
    pump_modeled_until(
        &scenario.network,
        &scenario.macs,
        25,
        700,
        |node_index, _, event| {
            let Some(packet) = received_of_type(event, PacketType::Broadcast) else {
                return;
            };
            if packet.payload_bytes() != b"mixed-broadcast" {
                return;
            }
            if node_index == alice {
                alice_broadcast.set(alice_broadcast.get() + 1);
            }
            if node_index == bob {
                bob_broadcast.set(bob_broadcast.get() + 1);
            }
        },
        || alice_broadcast.get() == 1 && bob_broadcast.get() == 1,
        "the broadcast phase should still flood across the same mesh",
    );
}

#[test]
fn receive_one_repeater_does_not_forward_reserved_packet_type_five() {
    // Packet type 5 remains opaque and non-routable until the protocol assigns
    // it explicit forwarding semantics.
    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    let repeater_id = repeater
        .add_identity(DummyIdentity::new([0x10; 32]))
        .unwrap();
    let repeater_hint = repeater
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let frame = build_reserved5_frame(
        Some((2, 2)),
        Some(&[repeater_hint]),
        Some(&[RouterHint([0x33, 0x44])]),
        b"opaque-five",
    );
    repeater.radio_mut().queue_received_frame(frame.as_slice());

    let handled = block_on(repeater.receive_one(|_, _| {})).unwrap();
    assert!(!handled);
    assert!(repeater.tx_queue_mut().pop_next().is_none());
}

#[test]
fn poll_cycle_drains_tx_receives_unicast_and_sends_immediate_ack() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 16],
        k_mic: [2; 16],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"queued", None, None)
        .unwrap();
    mac.radio_mut()
        .queue_received_unicast(&remote, &keys, &dst_hint, b"hello", true);

    let mut seen = None;
    block_on(mac.poll_cycle(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((
                identity,
                packet.from_key().unwrap(),
                packet.payload_bytes().to_vec(),
                packet.ack_requested(),
            ));
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
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next();
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    let mut seen = None;
    block_on(mac.poll_cycle(|identity, event| {
        if let MacEventRef::AckTimeout { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    }))
    .unwrap();

    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

#[test]
fn confirmed_forwarded_send_no_longer_retries_on_confirmation_timeout() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

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
    let original_frame = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    mac.radio_mut()
        .queue_received_frame(original_frame.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
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
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

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

    let original_frame = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    let forwarded_frame = rewrite_forwarded_fixture(original_frame.as_slice());
    mac.radio_mut()
        .queue_received_frame(forwarded_frame.as_slice());
    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(handled);
    assert!(matches!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .unwrap()
            .state,
        AckState::AwaitingAck
    ));

    let ack_tag = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_tag;
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();
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
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

#[test]
fn poll_cycle_prefers_mac_ack_over_same_cycle_timeout() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    let ack_tag = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_tag;
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    let _ = mac.tx_queue_mut().pop_next();
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
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
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

#[test]
fn send_receipts_wrap_from_u32_max_back_to_zero() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();
    mac.identity_mut(local_id)
        .unwrap()
        .set_next_receipt_for_test(u32::MAX);

    let first = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"first",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    let second = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"second",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(first, SendReceipt(u32::MAX));
    assert_eq!(second, SendReceipt(0));
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&first)
            .is_some()
    );
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&second)
            .is_some()
    );
}

#[test]
fn service_pending_ack_timeouts_emits_timeout_and_removes_entry() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    mac.tx_queue_mut().pop_next();
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    let mut seen = None;
    mac.service_pending_ack_timeouts(|identity, event| {
        if let MacEventRef::AckTimeout { peer, receipt } = event {
            seen = Some((identity, peer, receipt));
        }
    })
    .unwrap();

    assert_eq!(seen, Some((local_id, peer_key, receipt)));
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

#[test]
fn service_pending_ack_timeouts_requeues_forwarded_retry() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

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
    pending.ack_deadline_ms = 999_999;
    pending.state = AckState::AwaitingForward {
        confirm_deadline_ms: 0,
    };

    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();

    let retry = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(retry.priority, TxPriority::Retry);
    assert_eq!(retry.receipt, Some(receipt));
    assert!(retry.not_before_ms >= mac.clock().now_ms());

    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert_eq!(pending.retries, 1);
    assert!(matches!(pending.state, AckState::RetryQueued));
}

#[test]
fn service_pending_ack_timeouts_reroutes_failed_source_route_once() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let mut route = heapless::Vec::new();
    route.push(RouterHint([1, 2])).unwrap();
    let mut options = SendOptions::default().with_ack_requested(true).no_flood();
    options.source_route = Some(route.clone());

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    let original = mac.tx_queue_mut().pop_next().unwrap();
    let original_frame = original.frame.clone();

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    let mut timeout_seen = None;
    mac.service_pending_ack_timeouts(|identity, event| {
        if let MacEventRef::AckTimeout { peer, receipt } = event {
            timeout_seen = Some((identity, peer, receipt));
        }
    })
    .unwrap();

    assert!(timeout_seen.is_none());

    let retry = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(retry.priority, TxPriority::Retry);
    assert_eq!(retry.receipt, Some(receipt));

    let retry_header = PacketHeader::parse(retry.frame.as_slice()).unwrap();
    let retry_options = ParsedOptions::extract(retry.frame.as_slice(), retry_header.options_range.clone()).unwrap();
    assert!(retry_options.route_retry);
    assert!(retry_options.trace_route.is_some());
    assert!(retry_options.source_route.is_none());
    assert_eq!(retry_header.flood_hops.unwrap().remaining(), 1);

    let original_header = PacketHeader::parse(original_frame.as_slice()).unwrap();
    assert_eq!(
        &retry.frame.as_slice()[retry_header.mic_range.clone()],
        &original_frame.as_slice()[original_header.mic_range.clone()]
    );

    let pending = mac.identity(local_id).unwrap().pending_ack(&receipt).unwrap();
    assert!(matches!(pending.state, AckState::RetryQueued));
    assert_eq!(pending.retries, 0);
    assert_eq!(pending.ack_deadline_ms, 0);
    assert!(pending.resend.source_route.is_none());
    let pending_header = PacketHeader::parse(pending.resend.frame.as_slice()).unwrap();
    let pending_options = ParsedOptions::extract(
        pending.resend.frame.as_slice(),
        pending_header.options_range.clone(),
    )
    .unwrap();
    assert!(pending_options.route_retry);
}

#[test]
fn queued_retry_does_not_rearm_forward_confirmation_before_retransmit() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

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
    pending.ack_deadline_ms = 999_999;
    pending.state = AckState::AwaitingForward {
        confirm_deadline_ms: 0,
    };

    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    assert!(matches!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .unwrap()
            .state,
        AckState::RetryQueued
    ));
}

#[test]
fn complete_ack_matches_receipt_and_clears_pending_entry() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = PublicKey([0xAB; 32]);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 16],
            k_mic: [2; 16],
        },
    )
    .unwrap();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    let ack_tag = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_tag;

    assert_eq!(
        mac.complete_ack(&peer_key, &ack_tag),
        Some((local_id, receipt))
    );
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

fn received_of_type<'a>(
    event: &'a MacEventRef<'a>,
    packet_type: PacketType,
) -> Option<&'a crate::ReceivedPacketRef<'a>> {
    match event {
        MacEventRef::Received(packet) if packet_matches(packet.packet_type(), packet_type) => {
            Some(packet)
        }
        _ => None,
    }
}

fn is_received_type(event: &MacEventRef<'_>, packet_type: PacketType) -> bool {
    received_of_type(event, packet_type).is_some()
}

fn packet_matches(actual: PacketType, expected: PacketType) -> bool {
    match expected {
        PacketType::Unicast => {
            matches!(actual, PacketType::Unicast | PacketType::UnicastAckReq)
        }
        PacketType::BlindUnicast => {
            matches!(
                actual,
                PacketType::BlindUnicast | PacketType::BlindUnicastAckReq
            )
        }
        _ => actual == expected,
    }
}

fn duplicate_key_for_secure_frame(frame: &[u8]) -> DupCacheKey {
    let header = PacketHeader::parse(frame).unwrap();
    let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();
    let mic = &frame[header.mic_range];
    let mut bytes = [0u8; 16];
    bytes[..mic.len()].copy_from_slice(mic);
    DupCacheKey::Mic {
        bytes,
        len: mic.len() as u8,
        route_retry: options.route_retry,
    }
}

fn make_mac() -> Mac<DummyPlatform, 4, 16, 8, 16, 16, 256, 64> {
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(DummyAes, DummySha),
        DummyClock {
            now_ms: Cell::new(123),
        },
        DummyRng(7),
        DummyCounterStore::default(),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn make_small_peer_mac<const PEERS: usize>() -> Mac<DummyPlatform, 4, PEERS, 8, 16, 16, 256, 64> {
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(DummyAes, DummySha),
        DummyClock {
            now_ms: Cell::new(123),
        },
        DummyRng(7),
        DummyCounterStore::default(),
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
    let builder = if ack_requested {
        builder.ack_requested()
    } else {
        builder
    };
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
        let header = packet.header().unwrap();
        packet.as_bytes_mut()[header.options_range.end] =
            FloodHops::new(remaining, accumulated).unwrap().0;
    }
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, keys)
        .unwrap();

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
    let builder = if ack_requested {
        builder.ack_requested()
    } else {
        builder
    };
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

fn encode_echo_command_payload(command_id: u8, data: &[u8]) -> heapless::Vec<u8, 32> {
    let mut payload = heapless::Vec::new();
    payload.push(PayloadType::MacCommand as u8).unwrap();
    payload.push(command_id).unwrap();
    payload.extend_from_slice(data).unwrap();
    payload
}

fn decrypt_unicast_payload(frame: &[u8], keys: &PairwiseKeys) -> heapless::Vec<u8, 256> {
    let engine = CryptoEngine::new(DummyAes, DummySha);
    let mut buf = [0u8; 256];
    buf[..frame.len()].copy_from_slice(frame);
    let header = PacketHeader::parse(&buf[..frame.len()]).unwrap();
    let body = engine
        .open_packet(&mut buf[..frame.len()], &header, keys)
        .unwrap();
    let mut payload = heapless::Vec::new();
    payload.extend_from_slice(&buf[body]).unwrap();
    payload
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match Future::poll(future.as_mut(), &mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

fn noop_waker() -> Waker {
    fn noop_raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            noop_raw_waker()
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        RawWaker::new(
            core::ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    unsafe { Waker::from_raw(noop_raw_waker()) }
}

fn poll_radio_once<R: Radio<Error = ()>>(
    radio: &mut R,
    buf: &mut [u8],
) -> Poll<Result<RxInfo, ()>> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    radio.poll_receive(&mut cx, buf)
}

type DeepModeledMac = crate::test_support::ModeledTestMac<4, 16, 8, 16, 16, 256, 64>;

struct ModeledScenario {
    network: crate::test_support::ModeledNetwork,
    macs: Vec<RefCell<DeepModeledMac>>,
    identity_ids: Vec<LocalIdentityId>,
    keys: Vec<PublicKey>,
    radio_ids: Vec<usize>,
}

fn build_modeled_line_scenario(node_count: usize) -> ModeledScenario {
    let clock = crate::test_support::DummyClock::new(0);
    let network = crate::test_support::ModeledNetwork::with_clock(clock.clone());
    let mut macs = Vec::new();
    let mut identity_ids = Vec::new();
    let mut keys = Vec::new();
    let mut radio_ids = Vec::new();

    for index in 0..node_count {
        let radio = network.add_radio_with_config(256, 50);
        radio_ids.push(radio.id());
        let mut mac = crate::test_support::make_modeled_test_mac(radio, clock.clone());
        mac.repeater_config_mut().enabled = index > 0 && index + 1 < node_count;
        let id = mac
            .add_identity(crate::test_support::DummyIdentity::new([
                0x10u8.wrapping_add(index as u8);
                32
            ]))
            .unwrap();
        let key = *mac.identity(id).unwrap().identity().public_key();
        identity_ids.push(id);
        keys.push(key);
        macs.push(RefCell::new(mac));
    }

    for index in 0..node_count.saturating_sub(1) {
        connect_modeled_bidirectional(&network, radio_ids[index], radio_ids[index + 1]);
    }

    ModeledScenario {
        network,
        macs,
        identity_ids,
        keys,
        radio_ids,
    }
}

fn install_endpoint_pairwise_keys(scenario: &mut ModeledScenario) {
    install_pairwise_keys_between(scenario, 0, scenario.keys.len() - 1);
}

fn install_pairwise_keys_between(scenario: &mut ModeledScenario, alice: usize, bob: usize) {
    let pairwise = PairwiseKeys {
        k_enc: [0x21; 16],
        k_mic: [0x42; 16],
    };

    {
        let mut alice_mac = scenario.macs[alice].borrow_mut();
        let peer_id = alice_mac.add_peer(scenario.keys[bob]).unwrap();
        alice_mac
            .install_pairwise_keys(scenario.identity_ids[alice], peer_id, pairwise.clone())
            .unwrap();
    }
    {
        let mut bob_mac = scenario.macs[bob].borrow_mut();
        let peer_id = bob_mac.add_peer(scenario.keys[alice]).unwrap();
        bob_mac
            .install_pairwise_keys(scenario.identity_ids[bob], peer_id, pairwise)
            .unwrap();
    }
}

fn connect_modeled_bidirectional(
    network: &crate::test_support::ModeledNetwork,
    a: usize,
    b: usize,
) {
    let profile = crate::test_support::ModeledLinkProfile {
        connected: true,
        base_rssi: -67,
        base_snr: Snr::from_decibels(9),
        rssi_jitter_dbm: 1,
        snr_jitter_centibels: 5,
        propagation_delay_ms: 3,
        drop_per_thousand: 0,
    };
    network.set_link_profile(a, b, profile);
    network.set_link_profile(b, a, profile);
}

fn connect_modeled_bidirectional_with_profile(
    network: &crate::test_support::ModeledNetwork,
    a: usize,
    b: usize,
    profile: crate::test_support::ModeledLinkProfile,
) {
    network.set_link_profile(a, b, profile);
    network.set_link_profile(b, a, profile);
}

fn disconnect_modeled_bidirectional(
    network: &crate::test_support::ModeledNetwork,
    a: usize,
    b: usize,
) {
    network.disconnect(a, b);
    network.disconnect(b, a);
}

fn pump_modeled_until(
    network: &crate::test_support::ModeledNetwork,
    macs: &[RefCell<DeepModeledMac>],
    step_ms: u64,
    max_steps: usize,
    mut on_event: impl FnMut(usize, LocalIdentityId, &MacEventRef<'_>),
    mut done: impl FnMut() -> bool,
    waiting_for: &str,
) {
    for _ in 0..max_steps {
        if done() {
            return;
        }
        for (node_index, mac_cell) in macs.iter().enumerate() {
            let mut mac = mac_cell.borrow_mut();
            block_on(mac.poll_cycle(|identity, event| {
                on_event(node_index, identity, &event);
            }))
            .unwrap();
        }
        if done() {
            return;
        }
        network.advance_ms(step_ms);
    }
    panic!("timed out waiting for {waiting_for}");
}

fn install_channel_on_all(
    scenario: &mut ModeledScenario,
    channel_key: ChannelKey,
) -> ChannelId {
    let channel_id = scenario.macs[0]
        .borrow()
        .crypto()
        .derive_channel_id(&channel_key);
    for mac in &scenario.macs {
        mac.borrow_mut().add_channel(channel_key.clone()).unwrap();
    }
    channel_id
}

fn build_reserved5_frame(
    flood_hops: Option<(u8, u8)>,
    source_route: Option<&[RouterHint]>,
    trace_route: Option<&[RouterHint]>,
    body: &[u8],
) -> heapless::Vec<u8, 256> {
    let mut frame = [0u8; 256];
    let mut options_buf = [0u8; 128];
    let mut encoder = umsh_core::options::OptionEncoder::new(&mut options_buf);

    if let Some(route) = trace_route {
        let mut encoded = [0u8; 30];
        let mut used = 0usize;
        for hop in route {
            encoded[used..used + 2].copy_from_slice(&hop.0);
            used += 2;
        }
        encoder
            .put(OptionNumber::TraceRoute.as_u16(), &encoded[..used])
            .unwrap();
    }
    if let Some(route) = source_route {
        let mut encoded = [0u8; 30];
        let mut used = 0usize;
        for hop in route {
            encoded[used..used + 2].copy_from_slice(&hop.0);
            used += 2;
        }
        encoder
            .put(OptionNumber::SourceRoute.as_u16(), &encoded[..used])
            .unwrap();
    }
    let options_len = if source_route.is_some() || trace_route.is_some() {
        encoder.end_marker().unwrap();
        encoder.finish()
    } else {
        0
    };

    let has_options = options_len > 0;
    let has_flood_hops = flood_hops.is_some();
    frame[0] = umsh_core::Fcf::new(PacketType::Reserved5, false, has_options, has_flood_hops).0;
    let mut cursor = 1usize;
    if has_options {
        frame[cursor..cursor + options_len].copy_from_slice(&options_buf[..options_len]);
        cursor += options_len;
    }
    if let Some((remaining, accumulated)) = flood_hops {
        frame[cursor] = FloodHops::new(remaining, accumulated).unwrap().0;
        cursor += 1;
    }
    frame[cursor..cursor + body.len()].copy_from_slice(body);
    cursor += body.len();

    let mut stored = heapless::Vec::new();
    stored.extend_from_slice(&frame[..cursor]).unwrap();
    stored
}

struct DummyIdentity {
    public_key: PublicKey,
}
impl DummyIdentity {
    fn new(bytes: [u8; 32]) -> Self {
        Self {
            public_key: PublicKey(bytes),
        }
    }
}

impl NodeIdentity for DummyIdentity {
    type Error = ();
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    async fn sign(&self, _message: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok([0u8; 64])
    }
    async fn agree(&self, _peer: &PublicKey) -> Result<SharedSecret, Self::Error> {
        Ok(SharedSecret([0u8; 32]))
    }
}

struct DummyCipher;
impl AesCipher for DummyCipher {
    fn encrypt_block(&self, _block: &mut [u8; 16]) {}
    fn decrypt_block(&self, _block: &mut [u8; 16]) {}
}

struct DummyAes;
impl AesProvider for DummyAes {
    type Cipher = DummyCipher;
    fn new_cipher(&self, _key: &[u8; 16]) -> Self::Cipher {
        DummyCipher
    }
}

struct DummySha;
impl Sha256Provider for DummySha {
    fn hash(&self, data: &[&[u8]]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = data
            .iter()
            .map(|chunk| chunk.len() as u8)
            .fold(0, u8::wrapping_add);
        out
    }
    fn hmac(&self, key: &[u8], data: &[&[u8]]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = key.len() as u8;
        out[1] = data
            .iter()
            .map(|chunk| chunk.len() as u8)
            .fold(0, u8::wrapping_add);
        out
    }
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

    fn queue_received_mac_ack(&mut self, dst: NodeHint, ack_tag: [u8; 8]) {
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .mac_ack(dst, ack_tag)
            .build()
            .unwrap();
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
        self.queue_received_unicast_with_route(
            source,
            keys,
            dst,
            payload,
            ack_requested,
            7,
            None,
            None,
            None,
        );
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
        let builder = if ack_requested {
            builder.ack_requested()
        } else {
            builder
        };
        let mut packet = builder.payload(payload).build().unwrap();
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, keys)
            .unwrap();
        self.queue_received_frame(packet.as_bytes());
    }

    fn queue_received_unicast_with_route(
        &mut self,
        source: &DummyIdentity,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
        frame_counter: u32,
        flood_hops: Option<(u8, u8)>,
        trace_route: Option<&[RouterHint]>,
        source_route: Option<&[RouterHint]>,
    ) {
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .unicast(*dst)
            .source_full(source.public_key())
            .frame_counter(frame_counter)
            .encrypted();
        let builder = if ack_requested {
            builder.ack_requested()
        } else {
            builder
        };
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
            let header = packet.header().unwrap();
            packet.as_bytes_mut()[header.options_range.end] =
                FloodHops::new(remaining, accumulated).unwrap().0;
        }
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, keys)
            .unwrap();
        let mut stored = heapless::Vec::new();
        for byte in packet.as_bytes() {
            stored.push(*byte).unwrap();
        }
        self.received.push_back(stored).unwrap();
    }

    fn queue_received_unicast_with_counter(
        &mut self,
        source: &DummyIdentity,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
        ack_requested: bool,
        frame_counter: u32,
    ) {
        self.queue_received_unicast_with_route(
            source,
            keys,
            dst,
            payload,
            ack_requested,
            frame_counter,
            None,
            None,
            None,
        );
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
        self.queue_received_blind_unicast_with_route(
            source,
            pairwise,
            channel_keys,
            dst,
            payload,
            ack_requested,
            None,
        );
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
        let builder = if ack_requested {
            builder.ack_requested()
        } else {
            builder
        };
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
        let builder = if ack_requested {
            builder.ack_requested()
        } else {
            builder
        };
        let mut packet = builder.payload(payload).build().unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, channel_keys)
            .unwrap();
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
        let builder = if ack_requested {
            builder.ack_requested()
        } else {
            builder
        };
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
            let header = packet.header().unwrap();
            packet.as_bytes_mut()[header.options_range.end] =
                FloodHops::new(remaining, accumulated).unwrap().0;
        }
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, keys)
            .unwrap();
        self.queue_received_frame(packet.as_bytes());
    }
}

impl Radio for DummyRadio {
    type Error = ();
    async fn transmit(
        &mut self,
        data: &[u8],
        options: TxOptions,
    ) -> Result<(), TxError<Self::Error>> {
        if options.cad_timeout_ms.is_some() {
            self.cad_calls = self.cad_calls.wrapping_add(1);
            if self.cad_responses.pop_front().unwrap_or(false) {
                return Err(TxError::CadTimeout);
            }
        }
        let mut stored = heapless::Vec::new();
        for byte in data {
            stored.push(*byte).unwrap();
        }
        self.transmitted.push(stored).unwrap();
        Ok(())
    }
    fn poll_receive(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<RxInfo, Self::Error>> {
        let Some(frame) = self.received.pop_front() else {
            return Poll::Pending;
        };
        buf[..frame.len()].copy_from_slice(frame.as_slice());
        Poll::Ready(Ok(RxInfo {
            len: frame.len(),
            rssi: 0,
            snr: Snr::from_decibels(0),
            lqi: None,
        }))
    }
    fn max_frame_size(&self) -> usize {
        255
    }
    fn t_frame_ms(&self) -> u32 {
        100
    }
}

struct DummyClock {
    now_ms: Cell<u64>,
}

impl DummyClock {
    fn advance_ms(&self, delta_ms: u64) {
        self.now_ms.set(self.now_ms.get().saturating_add(delta_ms));
    }
}

impl Clock for DummyClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.get()
    }
}

#[derive(Clone, Copy, Default)]
struct DummyDelay;

impl DelayNs for DummyDelay {
    async fn delay_ns(&mut self, _ns: u32) {}
}

struct DummyRng(u8);
impl TryRng for DummyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

impl TryCryptoRng for DummyRng {}

#[derive(Default)]
struct DummyCounterStore {
    loaded: RefCell<BTreeMap<std::vec::Vec<u8>, u32>>,
    stored: RefCell<std::vec::Vec<(std::vec::Vec<u8>, u32)>>,
    flushes: Cell<u32>,
}

impl CounterStore for DummyCounterStore {
    type Error = ();
    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        Ok(*self.loaded.borrow().get(context).unwrap_or(&0))
    }
    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        self.loaded.borrow_mut().insert(context.to_vec(), value);
        self.stored.borrow_mut().push((context.to_vec(), value));
        Ok(())
    }
    async fn flush(&self) -> Result<(), Self::Error> {
        self.flushes.set(self.flushes.get().wrapping_add(1));
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct DummyKeyValueStore;

impl KeyValueStore for DummyKeyValueStore {
    type Error = ();

    async fn load(&self, _key: &[u8], _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }

    async fn store(&self, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn delete(&self, _key: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DummyPlatform;

impl Platform for DummyPlatform {
    type Identity = DummyIdentity;
    type Aes = DummyAes;
    type Sha = DummySha;
    type Radio = DummyRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = DummyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}
