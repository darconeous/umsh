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
    PacketType, PayloadType, PublicKey, RouterHint, iter_options,
};
use umsh_crypto::{
    AesCipher, AesProvider, CryptoEngine, DerivedChannelKeys, NodeIdentity, PairwiseKeys,
    Sha256Provider, SharedSecret,
};
use umsh_hal::{Clock, CounterStore, KeyValueStore, Radio, RxInfo, TxError, TxOptions};

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
    mac.install_pairwise_keys(local_id, peer_id, keys.clone()).unwrap();
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
    let pending = PendingAck::direct([0xAA; 8], PublicKey([0x11; 32]), resend, 10, 100);
    assert_eq!(pending.state, AckState::AwaitingAck);
}

#[test]
fn forwarded_ack_requested_starts_awaiting_forward() {
    let resend: ResendRecord =
        ResendRecord::try_new(b"hello", Some(&[RouterHint([1, 2])])).unwrap();
    let pending = PendingAck::forwarded([0xBB; 8], PublicKey([0x22; 32]), resend, 10, 100, 25);
    assert_eq!(
        pending.state,
        AckState::AwaitingForward {
            confirm_deadline_ms: 25
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
        PendingAck::direct([0xAA; 8], PublicKey([1; 32]), resend.clone(), 1, 2),
    )
    .unwrap();
    let second_receipt = slot.next_receipt();

    assert_eq!(
        slot.try_insert_pending_ack(
            second_receipt,
            PendingAck::direct([0xBB; 8], PublicKey([2; 32]), resend, 1, 2)
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
            seen.push((identity, packet.from_key().unwrap(), body)).unwrap();
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
    assert!(mac
        .identity(local_id)
        .unwrap()
        .peer_crypto()
        .get(&peer_id)
        .is_some());
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
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        &response,
        false,
        8,
    );

    let mut delivered = std::vec::Vec::new();
    assert!(block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            assert_eq!(identity, local_id);
            delivered.push(packet.payload_bytes().to_vec());
        }
    }))
    .unwrap());
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
    assert!(block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            delivered_again = Some((identity, packet.payload_bytes().to_vec()));
        }
    }))
    .unwrap());
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
    assert!(mac
        .identity(local_id)
        .unwrap()
        .peer_crypto()
        .get(&peer_id)
        .is_some());
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

    let second_keys = mac
        .crypto()
        .derive_pairwise_keys(&SharedSecret([1u8; 32]));
    mac.radio_mut()
        .queue_received_unicast(&second_remote, &second_keys, &dst_hint, b"second", false);

    let mut seen = None;
    assert!(block_on(mac.receive_one(|identity, event| {
        if let Some(packet) = received_of_type(&event, PacketType::Unicast) {
            seen = Some((identity, packet.from_key(), packet.payload_bytes().to_vec()));
        }
    }))
    .unwrap());

    assert_eq!(
        seen,
        Some((local_id, Some(second_key), b"second".to_vec()))
    );
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
    assert!(mac
        .identity(local_id)
        .unwrap()
        .peer_crypto()
        .get(&peer_id)
        .is_some());
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
    assert!(mac
        .identity(local_id)
        .unwrap()
        .peer_crypto()
        .get(&peer_id)
        .is_some());
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

    mac.radio_mut().queue_received_blind_unicast_with_source_hint(
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
fn receive_one_learns_reversed_trace_route_for_unicast_sender() {
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
            heapless::Vec::from_slice(&[RouterHint([0x03, 0x04]), RouterHint([0x01, 0x02])])
                .unwrap()
        ))
    );
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
    assert!(forwarded.not_before_ms <= 223);

    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    assert_eq!(header.flood_hops.unwrap(), FloodHops::new(3, 3).unwrap());
}

#[test]
fn receive_one_cancels_pending_forward_when_duplicate_is_overheard() {
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
    mac.identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap()
        .ack_deadline_ms = 0;

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
    mac.identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap()
        .ack_deadline_ms = 0;
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
    pending.state = AckState::AwaitingForward {
        confirm_deadline_ms: 0,
    };

    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();

    let retry = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(retry.priority, TxPriority::Retry);
    assert_eq!(retry.receipt, Some(receipt));

    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert_eq!(pending.retries, 1);
    assert!(matches!(pending.state, AckState::AwaitingForward { .. }));
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
            matches!(actual, PacketType::BlindUnicast | PacketType::BlindUnicastAckReq)
        }
        _ => actual == expected,
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
    let body = engine.open_packet(&mut buf[..frame.len()], &header, keys).unwrap();
    let mut payload = heapless::Vec::new();
    payload.extend_from_slice(&buf[body]).unwrap();
    payload
}

fn block_on<F: Future>(future: F) -> F::Output {
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
            snr: 0,
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
