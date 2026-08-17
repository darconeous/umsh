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
    PacketType, ParsedOptions, PayloadType, PublicKey, RouterHint, feed_aad, iter_options,
    options::TraceSignalEntry,
};
use umsh_crypto::{
    AesCipher, AesProvider, CryptoEngine, DerivedChannelKeys, NodeIdentity, PairwiseKeys,
    Sha256Provider, SharedSecret,
};
use umsh_hal::{
    Clock, CounterStore, KeyValueStore, Radio, RxInfo, RxOrigin, Snr, TxError, TxOptions,
};

/// Helper that produces a 32-byte `PublicKey` test peers can pass to
/// `add_peer` without tripping the Ed25519 curve validator.
///
/// When the `software-crypto` feature is enabled (which it is when these
/// tests share a build graph with `umsh-node` and friends), the `seed`
/// byte pattern is run through Ed25519 derivation so the resulting key
/// lies on the curve. Otherwise — for example in pure-`alloc` test
/// builds where the validator is compiled out — the seed bytes are
/// returned verbatim, preserving the previous test wire-image where
/// callers expected `[0xAB; 32]` literally.
fn test_pubkey(seed: u8) -> PublicKey {
    #[cfg(feature = "software-crypto")]
    {
        *umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&[seed; 32]).public_key()
    }
    #[cfg(not(feature = "software-crypto"))]
    {
        PublicKey([seed; 32])
    }
}

#[test]
fn duplicate_cache_evicts_oldest_entry() {
    let mut cache = DuplicateCache::<2>::new();
    cache.insert(DupCacheKey::Hash32(1), 1);
    cache.insert(DupCacheKey::Hash32(2), 2);
    cache.insert(DupCacheKey::Hash32(3), 3);

    assert!(!cache.contains(&DupCacheKey::Hash32(1), 3));
    assert!(cache.contains(&DupCacheKey::Hash32(2), 3));
    assert!(cache.contains(&DupCacheKey::Hash32(3), 3));
}

#[test]
fn duplicate_cache_entries_age_out() {
    let mut cache = DuplicateCache::<4>::new();
    cache.insert(DupCacheKey::Hash32(1), 1_000);

    assert!(cache.contains(&DupCacheKey::Hash32(1), 1_000 + DUP_CACHE_TTL_MS - 1));
    assert!(!cache.contains(&DupCacheKey::Hash32(1), 1_000 + DUP_CACHE_TTL_MS));
}

/// A key repeated inside its window ages from when it was first seen, so a
/// node repeating itself cannot keep its own suppression alive indefinitely.
#[test]
fn duplicate_cache_repeat_does_not_extend_the_window() {
    let mut cache = DuplicateCache::<4>::new();
    cache.insert(DupCacheKey::Hash32(1), 0);
    cache.insert(DupCacheKey::Hash32(1), DUP_CACHE_TTL_MS / 2);

    assert!(!cache.contains(&DupCacheKey::Hash32(1), DUP_CACHE_TTL_MS));
}

/// Ack keys age out on their own short clock, so a destination's
/// deliberate re-acknowledgement can be forwarded again; a general key
/// holding the same hash value is a different key on the long clock.
#[test]
fn duplicate_cache_ages_ack_keys_out_fast() {
    let mut cache = DuplicateCache::<4>::new();
    cache.insert(DupCacheKey::AckHash32(7), 1_000);
    cache.insert(DupCacheKey::Hash32(7), 1_000);

    let ack_expiry = 1_000 + crate::cache::ACK_DUP_CACHE_TTL_MS;
    assert!(cache.contains(&DupCacheKey::AckHash32(7), ack_expiry - 1));
    assert!(!cache.contains(&DupCacheKey::AckHash32(7), ack_expiry));
    assert!(cache.contains(&DupCacheKey::Hash32(7), ack_expiry));
}

#[test]
fn route_retry_changes_authenticated_duplicate_key_without_changing_mic() {
    let source = DummyIdentity::new([0x11; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        .mac_ack([0xA5; 8])
        .build()
        .unwrap();
    let mut routed = [0u8; 256];
    let routed = PacketBuilder::new(&mut routed)
        .mac_ack([0xA5; 8])
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        .mac_ack([0xA5; 8])
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
        multicast.header().unwrap();
        multicast.as_bytes_mut()[1] = FloodHops::new(2, 0).unwrap().0;
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        .mac_ack([0xA5; 8])
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
        multicast.header().unwrap();
        multicast.as_bytes_mut()[1] = FloodHops::new(2, 0).unwrap().0;
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
fn duplicate_ack_window_requires_exact_recent_mic_within_eight_counters() {
    let mut window = ReplayWindow::new();
    let original_mic = [0xA5; 8];
    window.accept(10, &original_mic, 1);
    for counter in 11..=18 {
        window.accept(counter, &[counter as u8; 8], counter as u64);
    }

    assert!(window.note_acknowledgeable_duplicate(10, &original_mic, 19, 0));
    assert!(!window.note_acknowledgeable_duplicate(10, &[0x5A; 8], 19, 0));

    window.accept(19, &[19; 8], 20);
    assert!(!window.note_acknowledgeable_duplicate(10, &original_mic, 21, 0));
}

#[test]
fn duplicate_ack_window_uses_modular_counter_distance() {
    let mut window = ReplayWindow::new();
    let mic = [0xA5; 8];
    window.accept(u32::MAX, &mic, 1);
    // Model a highest accepted counter that has wrapped while retaining the
    // recent MIC for the packet immediately before the wrap.
    window.last_accepted = 1;

    assert!(window.note_acknowledgeable_duplicate(u32::MAX, &mic, 2, 0));
}

/// One ack per transmission, not one per copy: flood duplicates inside
/// the holdoff — of the accepted transmission or of a retransmission —
/// are covered by the ack that transmission already earned.
#[test]
fn duplicate_ack_window_holdoff_paces_flood_copies() {
    let mut window = ReplayWindow::new();
    let mic = [0xA5; 8];
    window.accept(10, &mic, 1_000);

    // Flood copies of the accepted transmission: the acceptance already
    // queued their ack.
    assert!(!window.note_acknowledgeable_duplicate(10, &mic, 1_800, 2_000));
    assert!(!window.note_acknowledgeable_duplicate(10, &mic, 2_500, 2_000));

    // A retransmission after the holdoff earns one re-ack...
    assert!(window.note_acknowledgeable_duplicate(10, &mic, 6_000, 2_000));
    // ...that also covers the retransmission's own flood copies.
    assert!(!window.note_acknowledgeable_duplicate(10, &mic, 6_700, 2_000));
    assert!(!window.note_acknowledgeable_duplicate(10, &mic, 7_900, 2_000));

    // A still later retransmission is re-acked again.
    assert!(window.note_acknowledgeable_duplicate(10, &mic, 9_000, 2_000));
}

#[test]
fn receive_one_auto_replies_to_echo_request() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_id = mac.add_peer(*remote.public_key()).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        &request,
        false,
        7,
        None,
        Some(&[]),
        None,
    );

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let response = mac.tx_queue_mut().pop_next().expect("echo response queued");
    let header = PacketHeader::parse(response.frame.as_slice()).unwrap();
    let options =
        ParsedOptions::extract(response.frame.as_slice(), header.options_range.clone()).unwrap();
    assert!(
        options.trace_route.is_some(),
        "echo response must preserve a trace-route request"
    );
    let payload = decrypt_unicast_payload(response.frame.as_slice(), &keys);
    assert_eq!(
        payload.as_slice(),
        encode_echo_command_payload(5, &[9, 8, 7, 6]).as_slice()
    );
}

/// A ping measures a link, and the signal entries are what make that
/// measurement per-hop. A response that mirrors only the route reports where
/// the frame went without reporting what any of it cost.
#[test]
fn echo_response_mirrors_a_trace_signal_request() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_id = mac.add_peer(*remote.public_key()).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        .queue_received_traced_echo_request(&remote, &keys, &dst_hint, &request);

    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let response = mac.tx_queue_mut().pop_next().expect("echo response queued");
    let header = PacketHeader::parse(response.frame.as_slice()).unwrap();
    let options =
        ParsedOptions::extract(response.frame.as_slice(), header.options_range.clone()).unwrap();
    assert!(options.trace_route.is_some());
    assert!(
        options.trace_signal.is_some(),
        "echo response must preserve a trace-signal request"
    );
}

#[test]
fn peer_registry_looks_up_by_hint_and_updates_route() {
    let mut registry = PeerRegistry::<4>::new();
    let key = test_pubkey(0xA1);
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
        k_enc: [1; 32],
        k_mic: [2; 32],
        channel_id: ChannelId([0xAA, 0xBB]),
    };
    let derived_b = umsh_crypto::DerivedChannelKeys {
        k_enc: [3; 32],
        k_mic: [4; 32],
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
    let pending = PendingAck::direct([0xAA; 8], test_pubkey(0x11), resend);
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
    let pending = PendingAck::forwarded([0xBB; 8], test_pubkey(0x22), resend);
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
    let peer = mac.add_peer(test_pubkey(0xAB)).unwrap();
    mac.add_channel(ChannelKey([0x5A; 32])).unwrap();

    assert_eq!(id_a, LocalIdentityId(0));
    assert_eq!(id_b, LocalIdentityId(1));
    assert_eq!(mac.identity_count(), 2);
    // The hint is the first three bytes of the identity's public key.
    // (Compute the expectation from the actual key rather than the seed:
    // under `software-crypto` the DummyIdentity seed derives a real Ed25519
    // public key rather than being used verbatim.)
    let id_b_key = *mac.identity(id_b).unwrap().identity().public_key();
    assert_eq!(
        mac.identity(id_b).unwrap().identity().hint(),
        umsh_core::NodeHint([id_b_key.0[0], id_b_key.0[1], id_b_key.0[2]])
    );
    assert_eq!(
        mac.peer_registry().get(peer).unwrap().public_key,
        test_pubkey(0xAB)
    );
    assert_eq!(mac.channels().len(), 1);
}

#[test]
fn remove_channel_by_key() {
    let mut mac = make_mac();
    let key = ChannelKey([0x5A; 32]);
    mac.add_channel(key).unwrap();
    assert_eq!(mac.channels().len(), 1);

    assert!(mac.remove_channel(&key));
    assert_eq!(mac.channels().len(), 0);
    // Removing an absent key reports false rather than failing.
    assert!(!mac.remove_channel(&key));

    // The slot is genuinely free again.
    mac.add_channel(key).unwrap();
    assert_eq!(mac.channels().len(), 1);
}

#[test]
fn remove_peer_rekeys_swap_moved_peer_state() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let first_key = test_pubkey(0xAB);
    let second_key = test_pubkey(0xCD);
    let first_id = mac.add_peer(first_key).unwrap();
    let second_id = mac.add_peer(second_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        first_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        },
    )
    .unwrap();
    mac.install_pairwise_keys(
        local_id,
        second_id,
        PairwiseKeys {
            k_enc: [3; 32],
            k_mic: [4; 32],
        },
    )
    .unwrap();

    // Removing the first peer swap-moves the second into its slot; the
    // second peer's crypto state must follow its new PeerId.
    assert!(mac.remove_peer(&first_key));
    assert!(mac.peer_registry().lookup_by_key(&first_key).is_none());
    let (moved_id, moved) = mac.peer_registry().lookup_by_key(&second_key).unwrap();
    assert_eq!(moved_id, first_id);
    assert_eq!(moved.public_key, second_key);
    let state = mac
        .identity(local_id)
        .unwrap()
        .peer_crypto()
        .get(&moved_id)
        .expect("moved peer keeps its crypto state under its new id");
    assert_eq!(state.pairwise_keys.k_enc, [3; 32]);
    // Nothing may linger under the vacated identifier's old key material.
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&second_id)
            .is_none()
    );

    // Removing an absent peer reports false; re-adding reuses the free slot.
    assert!(!mac.remove_peer(&first_key));
    let readded = mac.add_peer(first_key).unwrap();
    assert_eq!(readded, second_id);
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&readded)
            .is_none(),
        "a re-added peer starts without crypto state"
    );

    // Unicast to the moved peer still works through its re-keyed state.
    assert!(
        mac.queue_unicast(
            local_id,
            &second_key,
            b"still works",
            &SendOptions::default()
        )
        .is_ok()
    );
}

#[test]
fn remove_last_peer_needs_no_rekey() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let first_key = test_pubkey(0xAB);
    let second_key = test_pubkey(0xCD);
    let first_id = mac.add_peer(first_key).unwrap();
    let second_id = mac.add_peer(second_key).unwrap();
    mac.install_pairwise_keys(
        local_id,
        second_id,
        PairwiseKeys {
            k_enc: [3; 32],
            k_mic: [4; 32],
        },
    )
    .unwrap();

    assert!(mac.remove_peer(&second_key));
    assert!(mac.peer_registry().lookup_by_key(&second_key).is_none());
    assert!(
        mac.identity(local_id)
            .unwrap()
            .peer_crypto()
            .get(&second_id)
            .is_none()
    );
    // The remaining peer is untouched.
    let (kept_id, kept) = mac.peer_registry().lookup_by_key(&first_key).unwrap();
    assert_eq!(kept_id, first_id);
    assert_eq!(kept.public_key, first_key);
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
fn random_initial_frame_counter_never_uses_zero_sentinel() {
    assert_eq!(crate::coordinator::nonzero_initial_frame_counter(0), 1);
    assert_eq!(
        crate::coordinator::nonzero_initial_frame_counter(0xA5A5_5A5A),
        0xA5A5_5A5A
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

    // The persistence context is the identity's actual public key (which
    // under `software-crypto` is derived from the seed, not the seed itself).
    let context = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .0
        .to_vec();
    mac.counter_store().loaded.borrow_mut().insert(context, 128);

    let loaded = block_on(mac.load_persisted_counter(local_id)).unwrap();

    assert_eq!(loaded, 128);
    assert_eq!(mac.identity(local_id).unwrap().frame_counter(), 128);
    assert!(mac.counter_store().stored.borrow().is_empty());
    assert_eq!(mac.counter_store().flushes.get(), 0);
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
    let peer_key = test_pubkey(0xAB);
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
    let mac = umsh_sync::AsyncRefCell::new(make_mac());
    let handle = MacHandle::new(&mac);
    let handle_clone = handle.clone();

    let (local_id, peer_id, peer_key, receipt) = block_on(async {
        let local_id = handle
            .add_identity(DummyIdentity::new([0x10; 32]))
            .await
            .unwrap();
        let peer_key = test_pubkey(0xAB);
        let peer_id = handle_clone.add_peer(peer_key).await.unwrap();
        handle
            .install_pairwise_keys(
                local_id,
                peer_id,
                PairwiseKeys {
                    k_enc: [1; 32],
                    k_mic: [2; 32],
                },
            )
            .await
            .unwrap();

        let receipt = handle_clone
            .send_unicast(
                local_id,
                &peer_key,
                b"hello",
                &SendOptions::default().with_ack_requested(true).no_flood(),
            )
            .await
            .unwrap()
            .unwrap();
        (local_id, peer_id, peer_key, receipt)
    });
    let _ = peer_id;
    let _ = peer_key;

    let borrowed = mac.try_borrow().expect("handle should have released cell");
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
    let peer_key = test_pubkey(0xAB);
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

/// Options go on the wire in ascending number order, so an originated frame
/// that carries both a region code (11) and an operator callsign (4) only
/// builds if the callsign is emitted first.
#[test]
fn originated_frame_carries_both_a_region_code_and_an_operator_callsign() {
    let mut mac = make_mac();
    mac.operating_policy_mut().operator_callsign =
        Some(HamAddr::try_from_callsign("KZ2X").unwrap());
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    mac.queue_broadcast(
        local_id,
        b"hello",
        &SendOptions::default().with_region_code([0x78, 0x53]),
    )
    .unwrap();

    let frame = mac.tx_queue_mut().pop_next().unwrap();
    let frame = frame.frame.as_slice();
    let header = PacketHeader::parse(frame).unwrap();
    let numbers: heapless::Vec<u16, 8> = umsh_core::iter_options(frame, header.options_range)
        .map(|entry| entry.unwrap().0)
        .collect();

    assert_eq!(
        numbers.as_slice(),
        &[
            OptionNumber::OperatorCallsign.as_u16(),
            OptionNumber::RegionCode.as_u16()
        ]
    );
}

#[test]
fn licensed_only_mode_rejects_encrypted_unicast() {
    let mut mac = make_mac();
    mac.operating_policy_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    mac.operating_policy_mut().operator_callsign =
        Some(HamAddr::try_from_callsign("KZ2X").unwrap());

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
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
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
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
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
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
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
    // The renewal extends the reservation past the boundary the first send
    // already committed: one block beyond it, not the committed boundary
    // re-derived.
    assert_eq!(
        mac.identity(local_id).unwrap().pending_persist_target(),
        Some((initial_counter.wrapping_add(100 + 28 + 128)) & !127)
    );
}

#[test]
fn service_counter_persistence_writes_and_clears_pending_targets() {
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
    // Key the store entry by the identity's actual public key — the
    // persistence context — rather than the DummyIdentity seed.
    let context = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .0
        .to_vec();
    mac.counter_store().loaded.borrow_mut().insert(context, 255);

    let loaded = block_on(mac.load_persisted_counter(local_id)).unwrap();

    assert_eq!(loaded, 128);
    assert_eq!(mac.identity(local_id).unwrap().frame_counter(), 128);
    assert_eq!(mac.identity(local_id).unwrap().persisted_counter(), 128);
    assert!(mac.counter_store().stored.borrow().is_empty());
    assert_eq!(mac.counter_store().flushes.get(), 0);
}

#[test]
fn missing_counter_record_keeps_random_nonzero_start_without_writing() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let random_start = u32::from_le_bytes([7, 8, 9, 10]);

    let loaded = block_on(mac.load_persisted_counter(local_id)).unwrap();

    assert_eq!(loaded, random_start);
    assert_ne!(loaded, 0);
    assert!(mac.counter_store().stored.borrow().is_empty());
    assert_eq!(mac.counter_store().flushes.get(), 0);
}

#[test]
fn secure_send_blocks_when_counter_window_exhausted() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.identity_mut(local_id)
        .unwrap()
        .load_persisted_counter(0);
    mac.identity_mut(local_id).unwrap().set_frame_counter(128);
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

/// An identity that starts high in its persist block keeps sending.
///
/// The reservation is renewed from a position within the block, so an
/// identity whose counter starts past that position must still renew it.
/// Missing that renewal is unrecoverable rather than merely late: the gate
/// closes when the live counter reaches the committed boundary, and a
/// blocked send neither advances the counter nor schedules the write that
/// would move the boundary, so nothing left in the system can reopen it.
#[test]
fn secure_send_survives_the_boundary_when_the_counter_starts_late_in_its_block() {
    use crate::coordinator::COUNTER_PERSIST_BLOCK_SIZE;

    // Every block position a random initial counter could land on, not just
    // the handful past the renewal offset that exposed the bug.
    for start in 0..COUNTER_PERSIST_BLOCK_SIZE {
        let mut mac = make_mac();
        let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        // A fresh identity: nothing persisted yet, random nonzero counter at
        // an arbitrary position inside its persist block.
        mac.identity_mut(local_id)
            .unwrap()
            .load_persisted_counter(1024);
        mac.identity_mut(local_id)
            .unwrap()
            .set_frame_counter(1024 + start);
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

        // The event loop flushes pending boundaries after every wake; a send
        // and a flush in turn is the cadence a running node actually has.
        for send in 0..(3 * COUNTER_PERSIST_BLOCK_SIZE) {
            mac.queue_unicast(
                local_id,
                &peer_key,
                b"hello",
                &SendOptions::default().no_flood(),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "start {start}: send {send} refused with {error:?} at counter {}, \
                     persisted {}, pending {:?}",
                    mac.identity(local_id).unwrap().frame_counter(),
                    mac.identity(local_id).unwrap().persisted_counter(),
                    mac.identity(local_id).unwrap().pending_persist_target(),
                )
            });
            block_on(mac.service_counter_persistence()).unwrap();
            while mac.tx_queue_mut().pop_next().is_some() {}
        }
    }
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
    // Backoff is uniform over [T_frame/40, T_frame/4] — long enough for a frame
    // already on the air to finish, short enough that sixteen attempts stay
    // inside the sender's patience (channel-access.md § Backoff Procedure).
    let t_frame_ms = u64::from(mac.radio().t_frame_ms());
    let now_ms = mac.clock().now_ms();
    assert!(queued.not_before_ms >= now_ms + t_frame_ms / 40);
    assert!(queued.not_before_ms <= now_ms + t_frame_ms / 4);
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
fn transmit_next_drops_frame_after_sixteen_busy_cad_attempts() {
    let mut mac = make_mac();
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
    }
    mac.tx_queue_mut()
        .enqueue(
            TxPriority::Application,
            b"app",
            Some(SendReceipt(3)),
            Some(LocalIdentityId(0)),
        )
        .unwrap();

    let mut abandoned = std::vec::Vec::new();
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        let _ = block_on(mac.transmit_next(&mut |id, event| {
            if let crate::MacEventRef::TxAbandoned {
                identity_id,
                receipt,
            } = event
            {
                abandoned.push((id, identity_id, receipt));
            }
        }))
        .unwrap();
        mac.clock().advance_ms(1_000);
    }

    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.radio().cad_calls, crate::MAX_CAD_ATTEMPTS as u32);
    assert!(mac.radio().transmitted.is_empty());
    // The drop is accounted: exactly one TxAbandoned, on the final attempt.
    assert_eq!(
        abandoned.as_slice(),
        &[(LocalIdentityId(0), LocalIdentityId(0), Some(SendReceipt(3)))]
    );
}

#[test]
fn transmit_next_drops_identityless_frame_without_event_after_cad_exhaustion() {
    let mut mac = make_mac();
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
    }
    // No identity: a forwarded frame. Best-effort, dropped silently.
    mac.tx_queue_mut()
        .enqueue(TxPriority::Forward, b"fwd", None, None)
        .unwrap();

    let mut events = 0usize;
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        let _ = block_on(mac.transmit_next(&mut |_, _| events += 1)).unwrap();
        mac.clock().advance_ms(1_000);
    }

    assert!(mac.tx_queue().is_empty());
    assert!(mac.radio().transmitted.is_empty());
    assert_eq!(events, 0);
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
    let ack_trailer = [0xA5; 8];

    mac.queue_mac_ack(ack_trailer).unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.priority, TxPriority::ImmediateAck);
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(&queued.frame.as_slice()[header.mic_range], &ack_trailer);
}

#[test]
fn queue_mac_ack_for_peer_uses_cached_source_route_when_present() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(
            heapless::Vec::from_slice(&[RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])])
                .unwrap(),
        ),
    );

    mac.queue_mac_ack_for_peer(local_id, peer_id, [0xA5; 8], false)
        .unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    let options =
        ParsedOptions::extract(queued.frame.as_slice(), header.options_range.clone()).unwrap();
    let route = options
        .source_route
        .expect("mac ack should carry a source route");
    assert_eq!(queued.frame[route].len(), 4);
}

#[test]
fn queue_mac_ack_for_peer_uses_cached_flood_route_regions_when_present() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: 2,
            regions: heapless::Vec::from_slice(&[[0x31, 0xD9], [0x78, 0x53]]).unwrap(),
        },
    );

    mac.queue_mac_ack_for_peer(local_id, peer_id, [0xA5; 8], false)
        .unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert_eq!(header.flood_hops, Some(FloodHops::new(2, 0).unwrap()));
    let mut regions = std::vec::Vec::<[u8; 2]>::new();
    for entry in iter_options(queued.frame.as_slice(), header.options_range.clone()) {
        let (number, value) = entry.unwrap();
        if OptionNumber::from(number) != OptionNumber::RegionCode {
            continue;
        }
        regions.push([value[0], value[1]]);
    }
    assert_eq!(regions.as_slice(), &[[0x31, 0xD9], [0x78, 0x53]]);
}

/// A routed ack is a repeat-confirmed send: silence where the repeat
/// should be retries it, and the repeat — whenever it arrives — finishes
/// the entry and withdraws any retry still queued.
#[test]
fn routed_mac_ack_retries_until_its_repeat_is_heard() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(heapless::Vec::from_slice(&[RouterHint([0x01, 0x02])]).unwrap()),
    );

    mac.queue_mac_ack_for_peer(local_id, peer_id, [0xA5; 8], false)
        .unwrap();

    // The real transmit path arms the confirmation wait.
    block_on(mac.poll_cycle(|_, _| {})).unwrap();
    assert_eq!(mac.radio().transmitted.len(), 1);
    let (receipt, pending) = mac
        .identity(local_id)
        .unwrap()
        .pending_acks()
        .next()
        .expect("routed ack is tracked");
    let receipt = *receipt;
    assert!(!pending.expects_ack());
    assert!(matches!(pending.state, AckState::AwaitingForward { .. }));
    let ack_frame: std::vec::Vec<u8> = pending.resend.frame.to_vec();

    // Nothing repeats it: past the confirmation window (but short of the
    // ladder's terminal deadline) the identical frame is retransmitted.
    mac.clock().advance_ms(500);
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    let retry = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(retry.priority, TxPriority::Retry);
    assert_eq!(retry.receipt, Some(receipt));
    assert_eq!(retry.frame.as_slice(), ack_frame.as_slice());

    // Requeue the retry, then overhear the repeater carrying the ack
    // onward (route consumed): the entry completes and the queued retry
    // is withdrawn.
    mac.tx_queue_mut()
        .enqueue(
            TxPriority::Retry,
            retry.frame.as_slice(),
            Some(receipt),
            Some(local_id),
        )
        .unwrap();
    let mut buf = [0u8; 64];
    let forwarded = PacketBuilder::new(&mut buf)
        .mac_ack([0xA5; 8])
        .build()
        .unwrap();
    mac.radio_mut().queue_received_frame(forwarded);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_acks()
            .next()
            .is_none(),
        "the overheard repeat finishes the repeat-only ack"
    );
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "the queued retry is withdrawn with it"
    );
}

/// The ack an untracked path would drop: with no identity to track it,
/// a routed ack still goes out fire-and-forget.
#[test]
fn routed_mac_ack_without_identity_goes_untracked() {
    let mut mac = make_mac();
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(heapless::Vec::from_slice(&[RouterHint([0x01, 0x02])]).unwrap()),
    );

    mac.queue_mac_ack_for_peer(LocalIdentityId(0), peer_id, [0xA5; 8], false)
        .unwrap();

    let queued = mac.tx_queue_mut().pop_next().unwrap();
    assert_eq!(queued.receipt, None);
}

#[test]
fn queued_mac_ack_transmits_before_application_traffic() {
    let mut mac = make_mac();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", None, None)
        .unwrap();
    mac.queue_mac_ack([0xCC; 8]).unwrap();

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
        .ack_trailer;
    mac.radio_mut().queue_received_mac_ack(ack_tag);

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

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    mac.radio_mut().queue_received_mac_ack([0xEE; 8]);

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
    let peer_key = test_pubkey(0xAB);
    let peer_id = mac.add_peer(peer_key).unwrap();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.install_pairwise_keys(
        local_id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
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
        .ack_trailer;
    mac.radio_mut().queue_received_mac_ack(ack_tag);

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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    assert_eq!(header.mic_range.len(), 8);
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
fn receive_one_reacks_duplicate_unicast_within_eight_counter_window() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"original",
        true,
        10,
    );
    let mut deliveries = 0;
    assert!(
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Unicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );
    let original_ack = mac.tx_queue_mut().pop_next().unwrap().frame;

    for counter in 11..=18 {
        mac.radio_mut().queue_received_unicast_with_counter(
            &remote,
            &keys,
            &dst_hint,
            &[counter as u8],
            false,
            counter,
        );
        assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    }

    // Past the re-ack holdoff, so the duplicate reads as a sender
    // retransmission rather than a flood copy of the first delivery.
    mac.clock().advance_ms(10_000);
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"original",
        true,
        10,
    );
    assert!(
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::Unicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );
    let duplicate_ack = mac.tx_queue_mut().pop_next().unwrap().frame;

    assert_eq!(deliveries, 1);
    assert_eq!(duplicate_ack.as_slice(), original_ack.as_slice());

    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"advance outside window",
        false,
        19,
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"original",
        true,
        10,
    );
    assert!(!block_on(mac.receive_one(|_, _| {})).unwrap());
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    let (candidate_a, candidate_b) = colliding_hint_peer_keys();
    let _peer_a = mac.add_peer(candidate_a).unwrap();
    let peer_b = mac.add_peer(candidate_b).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    let pinned_key = test_pubkey(0xCD);
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    assert_eq!(header.mic_range.len(), 8);
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
fn receive_one_reacks_duplicate_blind_unicast_without_redelivery() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        true,
    );
    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        b"hello",
        true,
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
    let original_ack = mac.tx_queue_mut().pop_next().unwrap().frame;

    // Past the re-ack holdoff, so the duplicate reads as a sender
    // retransmission rather than a flood copy of the first delivery.
    mac.clock().advance_ms(10_000);
    assert!(
        block_on(mac.receive_one(|_, event| {
            if is_received_type(&event, PacketType::BlindUnicast) {
                deliveries += 1;
            }
        }))
        .unwrap()
    );
    let duplicate_ack = mac.tx_queue_mut().pop_next().unwrap().frame;

    assert_eq!(deliveries, 1);
    assert_eq!(duplicate_ack.as_slice(), original_ack.as_slice());
}

#[test]
fn receive_one_blind_unicast_with_ambiguous_hint_tries_candidate_peers() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let (candidate_a, candidate_b) = colliding_hint_peer_keys();
    let _peer_a = mac.add_peer(candidate_a).unwrap();
    let peer_b = mac.add_peer(candidate_b).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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

/// A MAC command is addressed to one node, and only a command whose own
/// definition provides rules for multicast or broadcast is acted on when it
/// arrives that way (mac-commands.md). The built-in Echo reply is not one of
/// them: answering a multicast ping would hand one frame a reply from every
/// member of the channel.
#[test]
fn receive_one_does_not_answer_an_echo_request_carried_by_multicast() {
    let mut mac = make_mac();
    let _local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_id = mac.crypto().derive_channel_id(&channel_key);
    mac.add_peer(*remote.public_key()).unwrap();
    mac.add_channel(channel_key.clone()).unwrap();

    let derived = mac.crypto().derive_channel_keys(&channel_key);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    // PayloadType::MacCommand, Echo Request, one byte of echo data.
    let echo_request = [PayloadType::MacCommand as u8, 4, 0x7E];
    mac.radio_mut()
        .queue_received_multicast(&remote, channel_id, &keys, &echo_request);

    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a multicast echo request must not raise a reply"
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
    let known_peer = test_pubkey(0xCD);
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
fn empty_trace_route_learns_a_direct_peer_and_originates_no_source_route_option() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    // A trace-route option that accumulated no hints: the packet arrived
    // without traversing a repeater.
    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        false,
        7,
        None,
        Some(&[]),
        None,
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    // That is a direct neighbour, not a zero-hop source route.
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Direct),
    );

    // So the reply must not carry a SourceRoute option at all. Only a
    // repeater consuming the final hint may leave an empty one behind.
    let options = SendOptions::default();
    let _ = block_on(mac.send_unicast(local_id, &peer_key, b"reply", &options)).unwrap();
    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    for entry in iter_options(queued.frame.as_slice(), header.options_range.clone()) {
        let (number, value) = entry.unwrap();
        assert_ne!(
            OptionNumber::from(number),
            OptionNumber::SourceRoute,
            "originated an empty source route: {value:02x?}",
        );
    }
}

/// Whether an already-built frame carries a trace-route option.
fn frame_has_trace_route(frame: &[u8]) -> bool {
    let header = PacketHeader::parse(frame).unwrap();
    ParsedOptions::extract(frame, header.options_range.clone())
        .unwrap()
        .trace_route
        .is_some()
}

/// A peer nothing is known about is reached by flooding, and the flood is
/// what discovers the path — so the frame records it whether or not the
/// application asked.
#[test]
fn unicast_to_an_unrouted_peer_carries_a_trace_route_unasked() {
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

    let _ =
        block_on(mac.send_unicast(local_id, &peer_key, b"hi", &SendOptions::default())).unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(frame_has_trace_route(queued.frame.as_slice()));
}

/// A flood distance says roughly how far away the peer is, not which
/// repeaters to go through. The trace stays on until a precise route replaces
/// the estimate.
#[test]
fn unicast_to_a_flood_distance_peer_still_carries_a_trace_route() {
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
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: 2,
            regions: heapless::Vec::new(),
        },
    );

    let _ =
        block_on(mac.send_unicast(local_id, &peer_key, b"hi", &SendOptions::default())).unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(frame_has_trace_route(queued.frame.as_slice()));
}

/// A frame that follows a source route already knows its path, and paying to
/// record it again is the proactive-refresh behavior the spec leaves
/// unspecified. This holds only while nothing has to come back — see
/// [`unicast_over_a_source_route_traces_when_it_asks_for_an_ack`].
#[test]
fn unicast_over_a_cached_source_route_carries_no_trace_route() {
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
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(heapless::Vec::from_slice(&[RouterHint([0x01, 0x02])]).unwrap()),
    );

    let _ =
        block_on(mac.send_unicast(local_id, &peer_key, b"hi", &SendOptions::default())).unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(!frame_has_trace_route(queued.frame.as_slice()));

    // Still available on request: the automatic trace is a floor, not a cap.
    let _ = block_on(mac.send_unicast(
        local_id,
        &peer_key,
        b"hi",
        &SendOptions::default().with_trace_route(),
    ))
    .unwrap();
    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(frame_has_trace_route(queued.frame.as_slice()));
}

/// The frame knows its path; the ack it asks for does not. A source route
/// arrives consumed, so nothing on the frame describes the way back, and the
/// destination composes its ack against an empty route cache: no flood
/// budget, no route, dead at the first hop. The trace the routed hops record
/// is the only thing that closes the return direction.
#[test]
fn unicast_over_a_source_route_traces_when_it_asks_for_an_ack() {
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
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(heapless::Vec::from_slice(&[RouterHint([0x01, 0x02])]).unwrap()),
    );

    let _ = block_on(mac.send_unicast(
        local_id,
        &peer_key,
        b"hi",
        &SendOptions::default().with_ack_requested(true),
    ))
    .unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(frame_has_trace_route(queued.frame.as_slice()));
    // The route still goes out: the trace rides alongside it, it does not
    // replace it.
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    let options = ParsedOptions::extract(queued.frame.as_slice(), header.options_range).unwrap();
    assert_eq!(
        queued.frame.as_slice()[options.source_route.unwrap()],
        [0x01, 0x02]
    );
}

/// A trace route asks repeaters to record themselves. With no flood budget
/// and no source route nothing may forward the frame at all, so the option
/// would arrive as empty as it left — a byte spent on a question no one is in
/// a position to answer.
#[test]
fn unrepeatable_unicast_carries_no_trace_route_even_to_an_unrouted_peer() {
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

    let _ = block_on(mac.send_unicast(
        local_id,
        &peer_key,
        b"hi",
        &SendOptions::default().no_flood(),
    ))
    .unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(!frame_has_trace_route(queued.frame.as_slice()));
}

/// The same rule on the reply side, and the case that actually reaches the
/// air: once the destination knows the sender is a direct neighbour its ack
/// carries no flood budget and no source route, so mirroring a trace onto it
/// puts an unanswerable option on every acknowledgement.
#[test]
fn mac_ack_to_a_directly_heard_peer_mirrors_no_trace_route() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    // Traced and flooded, but it arrived with an empty trace: a direct
    // neighbour, which is what the ack then has to route around.
    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        true,
        7,
        Some((3, 0)),
        Some(&[]),
        None,
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Direct)
    );
    let queued = mac.tx_queue_mut().pop_next().expect("queued mac ack");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    assert!(!frame_has_trace_route(queued.frame.as_slice()));
}

/// The evidence an empty trace route used to carry, read off the frame's own
/// shape. Nothing gave a repeater permission to carry this, so the only way
/// it arrived is directly — which is what lets the trace come off the wire.
#[test]
fn a_frame_nothing_could_have_repeated_proves_a_direct_link() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    // No flood hops, no source route, and no trace route either.
    mac.radio_mut().queue_received_unicast_with_route(
        &remote, &keys, &dst_hint, b"hello", false, 7, None, None, None,
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Direct)
    );
}

/// No repeater carries the frame, so there is nothing for a trace to record.
#[test]
fn unicast_to_a_directly_heard_peer_carries_no_trace_route() {
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
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);

    let _ =
        block_on(mac.send_unicast(local_id, &peer_key, b"hi", &SendOptions::default())).unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    assert!(!frame_has_trace_route(queued.frame.as_slice()));
}

/// The sender's trace taught us a path back; the mirrored trace on the ack is
/// the only thing that closes the other direction.
#[test]
fn mac_ack_mirrors_the_trace_route_of_the_frame_it_acknowledges() {
    for (sender_traced, expected) in [(true, true), (false, false)] {
        let mut mac = make_mac();
        let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let remote = DummyIdentity::new([0xAB; 32]);
        let peer_key = *remote.public_key();
        let peer_id = mac.add_peer(peer_key).unwrap();
        let keys = PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        };
        mac.install_pairwise_keys(local_id, peer_id, keys.clone())
            .unwrap();
        let dst_hint = mac
            .identity(local_id)
            .unwrap()
            .identity()
            .public_key()
            .hint();
        let trace = [RouterHint([0x01, 0x02])];

        mac.radio_mut().queue_received_unicast_with_route(
            &remote,
            &keys,
            &dst_hint,
            b"hello",
            true,
            7,
            None,
            sender_traced.then_some(trace.as_slice()),
            None,
        );
        assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

        let queued = mac.tx_queue_mut().pop_next().expect("queued mac ack");
        let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
        assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
        assert_eq!(
            frame_has_trace_route(queued.frame.as_slice()),
            expected,
            "sender_traced={sender_traced}",
        );
    }
}

/// A retransmission is the one frame carrying route information the original
/// did not, because reaching the retry ladder is itself the evidence that the
/// first ack never landed. Composing the re-ack from the stale cache instead
/// re-sends the same unroutable frame the sender is retrying against, and the
/// exchange never converges.
#[test]
fn a_retried_frame_teaches_its_route_before_the_re_ack_is_composed() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();
    let dst_hint = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    // First attempt: source-routed, so it arrives with its hints consumed and
    // nothing on it describes the way back.
    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        true,
        7,
        None,
        None,
        Some(&[]),
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let queued = mac.tx_queue_mut().pop_next().expect("queued mac ack");
    assert!(
        ParsedOptions::extract(
            queued.frame.as_slice(),
            PacketHeader::parse(queued.frame.as_slice())
                .unwrap()
                .options_range,
        )
        .unwrap()
        .source_route
        .is_none(),
        "nothing was known to route the first ack by",
    );
    assert_eq!(mac.peer_registry().get(peer_id).unwrap().route, None);

    // Past the re-ack holdoff, the sender retries — this time flooding, with a
    // trace to collect a replacement route. Same counter, same MIC: the
    // rewritten options are dynamic and excluded from the associated data.
    mac.clock().advance_ms(60_000);
    let trace = [RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])];
    mac.radio_mut().queue_received_unicast_with_route(
        &remote,
        &keys,
        &dst_hint,
        b"hello",
        true,
        7,
        Some((3, 2)),
        Some(trace.as_slice()),
        None,
    );
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Source(
            heapless::Vec::from_slice(&trace).unwrap()
        )),
        "the retry's trace is the route the sender asked us to learn",
    );
    let queued = mac.tx_queue_mut().pop_next().expect("queued re-ack");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.fcf.packet_type(), PacketType::MacAck);
    let options = ParsedOptions::extract(queued.frame.as_slice(), header.options_range).unwrap();
    assert_eq!(
        queued.frame.as_slice()[options
            .source_route
            .expect("re-ack carries the learned route")],
        [0x01, 0x02, 0x03, 0x04],
    );
}

/// An ack-only exchange produces exactly one packet back from the peer. If
/// its trace is discarded, a sender that never receives application traffic
/// from that peer never learns a route to it.
#[test]
fn trace_route_on_a_mac_ack_teaches_the_sender_the_way_back() {
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

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();
    let ack_trailer = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_trailer;
    let trace = [RouterHint([0x01, 0x02]), RouterHint([0x03, 0x04])];
    mac.radio_mut()
        .queue_received_mac_ack_with_trace(ack_trailer, &trace);

    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Source(
            heapless::Vec::from_slice(&trace).unwrap()
        ))
    );
}

#[test]
fn explicitly_empty_source_route_is_not_put_on_the_wire() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, keys.clone())
        .unwrap();

    let mut options = SendOptions::default();
    options.source_route = Some(heapless::Vec::new());
    let _ = block_on(mac.send_unicast(local_id, &peer_key, b"hi", &options)).unwrap();

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    for entry in iter_options(queued.frame.as_slice(), header.options_range.clone()) {
        let (number, _) = entry.unwrap();
        assert_ne!(OptionNumber::from(number), OptionNumber::SourceRoute);
    }
}

#[test]
fn send_unicast_uses_cached_source_route_when_present() {
    let mut mac = make_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = DummyIdentity::new([0xAB; 32]);
    let peer_key = *remote.public_key();
    let peer_id = mac.add_peer(peer_key).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    let flood_hops = header.flood_hops.expect("flood hops present");
    // The route spends no flood budget at all, so the wide first-contact
    // default collapses to the self-healing slack past the route's end.
    assert_eq!(flood_hops.remaining(), ESTABLISHED_ROUTE_EXTRA_HOPS);
}

/// Build a MAC with one local identity and one keyed peer, returning the
/// pieces the flood-budget tests need.
fn mac_with_keyed_peer() -> (TestMac, LocalIdentityId, PublicKey, PeerId) {
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
    (mac, local_id, peer_key, peer_id)
}

/// Send one unicast with `options` and report the `FHOPS_REM` it went out with.
fn queued_unicast_flood_hops(
    mac: &mut TestMac,
    local_id: LocalIdentityId,
    peer_key: &PublicKey,
    options: &SendOptions,
) -> Option<u8> {
    block_on(mac.send_unicast(local_id, peer_key, b"payload", options)).unwrap();
    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    header.flood_hops.map(|hops| hops.remaining())
}

#[test]
fn send_unicast_floods_at_full_budget_without_a_cached_route() {
    let (mut mac, local_id, peer_key, _) = mac_with_keyed_peer();

    let hops = queued_unicast_flood_hops(&mut mac, local_id, &peer_key, &SendOptions::default());

    assert_eq!(hops, Some(5));
}

#[test]
fn send_unicast_clamps_an_unencodable_flood_request_to_the_nibble_maximum() {
    let (mut mac, local_id, peer_key, _) = mac_with_keyed_peer();

    let hops = queued_unicast_flood_hops(
        &mut mac,
        local_id,
        &peer_key,
        &SendOptions::default().with_flood_hops(30),
    );

    // Without the clamp the builder drops the field outright, turning a
    // request to flood further into no flooding at all.
    assert_eq!(hops, Some(MAX_FLOOD_HOPS));
}

#[test]
fn send_unicast_narrows_flood_hops_to_the_slack_for_a_direct_peer() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);

    let hops = queued_unicast_flood_hops(&mut mac, local_id, &peer_key, &SendOptions::default());

    assert_eq!(hops, Some(ESTABLISHED_ROUTE_EXTRA_HOPS));
}

#[test]
fn send_unicast_narrows_flood_hops_to_the_learned_flood_distance() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: 2,
            regions: heapless::Vec::new(),
        },
    );

    let hops = queued_unicast_flood_hops(&mut mac, local_id, &peer_key, &SendOptions::default());

    assert_eq!(hops, Some(2 + ESTABLISHED_ROUTE_EXTRA_HOPS));
}

#[test]
fn send_unicast_treats_a_peer_heard_at_zero_hops_as_direct() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: 0,
            regions: heapless::Vec::new(),
        },
    );

    let hops = queued_unicast_flood_hops(&mut mac, local_id, &peer_key, &SendOptions::default());

    assert_eq!(hops, Some(ESTABLISHED_ROUTE_EXTRA_HOPS));
}

#[test]
fn send_unicast_never_raises_flood_hops_above_the_requested_budget() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: 9,
            regions: heapless::Vec::new(),
        },
    );

    let hops = queued_unicast_flood_hops(
        &mut mac,
        local_id,
        &peer_key,
        &SendOptions::default().with_flood_hops(3),
    );

    assert_eq!(hops, Some(3));
}

#[test]
fn send_unicast_keeps_flooding_disabled_for_a_routed_peer() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: 2,
            regions: heapless::Vec::new(),
        },
    );

    let hops = queued_unicast_flood_hops(
        &mut mac,
        local_id,
        &peer_key,
        &SendOptions::default().no_flood(),
    );

    assert_eq!(hops, None);
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
        Some(CachedRoute::Flood {
            hops: 2,
            regions: heapless::Vec::new(),
        })
    );
}

#[test]
fn receive_one_learns_flood_hops_and_regions_for_multicast_sender() {
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
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .multicast(channel_id)
        .source_full(remote.public_key())
        .frame_counter(11)
        .encrypted()
        .option(OptionNumber::RegionCode, &[0x31, 0xD9])
        .option(OptionNumber::RegionCode, &[0x78, 0x53])
        .flood_hops(4)
        .payload(b"group")
        .build()
        .unwrap();
    {
        packet.header().unwrap();
        packet.as_bytes_mut()[1] = FloodHops::new(4, 2).unwrap().0;
    }
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys)
        .unwrap();
    mac.radio_mut().queue_received_frame(packet.as_bytes());

    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    assert_eq!(
        mac.peer_registry().get(peer_id).unwrap().route,
        Some(CachedRoute::Flood {
            hops: 2,
            regions: heapless::Vec::from_slice(&[[0x31, 0xD9], [0x78, 0x53]]).unwrap(),
        })
    );
}

#[test]
fn receive_one_confirms_forwarded_send_when_same_frame_is_overheard() {
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    repeater
        .repeater_config_mut()
        .regions
        .push([0x78, 0x53])
        .unwrap();
    repeater.repeater_config_mut().default_region = Some([0x78, 0x53]);
    let repeater_id = repeater
        .add_identity(DummyIdentity::new([0x10; 32]))
        .unwrap();
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    let options =
        ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone()).unwrap();
    assert!(options.trace_route.is_none());
    assert_eq!(
        options.region_code, None,
        "a named hop forwards under the route, not under flood policy; the \
         first repeater to flood it tags the region"
    );
    assert_eq!(
        header
            .flood_hops
            .map(|hops| (hops.remaining(), hops.accumulated())),
        Some((5, 0)),
        "consuming the last source-route hint is still a source-routed hop \
         and must not spend flood budget"
    );
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
fn receive_one_repeater_ignores_signal_thresholds_for_source_routed_hops() {
    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    repeater.repeater_config_mut().min_rssi = Some(10);
    repeater.repeater_config_mut().min_snr = Some(10);
    let repeater_id = repeater
        .add_identity(DummyIdentity::new([0x10; 32]))
        .unwrap();
    let repeater_hint = repeater
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let dst = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    let source_route = [repeater_hint, RouterHint([0x21, 0x22])];

    repeater.radio_mut().queue_received_unicast_with_thresholds(
        &remote,
        &keys,
        &dst,
        b"hello",
        false,
        7,
        None,
        None,
        Some(&source_route),
        Some(20),
        Some(20),
    );

    let handled = block_on(repeater.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let forwarded = repeater.tx_queue_mut().pop_next().unwrap();
    assert_eq!(forwarded.priority, TxPriority::Forward);
}

/// Being the last hint in the route is still being named. The hop that empties
/// the route is a source-routed hop like any other, so signal thresholds — a
/// flood-forwarding policy — do not gate it.
#[test]
fn receive_one_repeater_ignores_signal_thresholds_on_the_final_source_routed_hop() {
    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    repeater.repeater_config_mut().min_rssi = Some(10);
    repeater.repeater_config_mut().min_snr = Some(10);
    let repeater_id = repeater
        .add_identity(DummyIdentity::new([0x10; 32]))
        .unwrap();
    let repeater_hint = repeater
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let dst = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    let source_route = [repeater_hint];

    repeater.radio_mut().queue_received_unicast_with_thresholds(
        &remote,
        &keys,
        &dst,
        b"hello",
        false,
        7,
        Some((1, 0)),
        None,
        Some(&source_route),
        Some(20),
        Some(20),
    );

    let handled = block_on(repeater.receive_one(|_, _| {})).unwrap();

    assert!(handled);
    let forwarded = repeater.tx_queue_mut().pop_next().unwrap();
    assert_eq!(forwarded.priority, TxPriority::Forward);
}

/// Once the route is empty the packet is a flood packet, and the first repeater
/// to carry it that way is subject to the full flood policy.
#[test]
fn receive_one_repeater_applies_signal_thresholds_when_hybrid_route_enters_flooding() {
    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    repeater.repeater_config_mut().min_rssi = Some(10);
    repeater.repeater_config_mut().min_snr = Some(10);
    repeater
        .add_identity(DummyIdentity::new([0x10; 32]))
        .unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let dst = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    // An empty-but-present source route: the provenance an upstream repeater
    // leaves behind after consuming the final hint.
    let source_route: [RouterHint; 0] = [];

    repeater.radio_mut().queue_received_unicast_with_thresholds(
        &remote,
        &keys,
        &dst,
        b"hello",
        false,
        7,
        Some((1, 0)),
        None,
        Some(&source_route),
        Some(20),
        Some(20),
    );

    let handled = block_on(repeater.receive_one(|_, _| {})).unwrap();

    assert!(!handled);
    assert!(repeater.tx_queue_mut().pop_next().is_none());
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
        .mac_ack([0xA5; 8])
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
    let options =
        ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone()).unwrap();
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    // The dummy radio reports 0 dBm, so the signal term saturates and the
    // deterministic window sits at its maximum; only the jitter varies.
    assert!(forwarded.not_before_ms >= 123 + 50);
    assert!(forwarded.not_before_ms <= 123 + 60);
    assert_eq!(forwarded.forward_deferrals, 0);

    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    assert_eq!(header.flood_hops.unwrap(), FloodHops::new(3, 3).unwrap());
}

#[test]
fn receive_one_repeater_adds_ack_guard_to_flood_forward_of_ack_requested_packet() {
    for ack_requested in [true, false] {
        let mut mac = make_mac();
        {
            let repeater = mac.repeater_config_mut();
            repeater.enabled = true;
            // Collapse the contention window and its jitter so the ACK
            // protection interval is the only delay component.
            repeater.flood_contention_min_window_percent = 0;
            repeater.flood_contention_max_window_percent = 0;
            repeater.flood_contention_jitter_percent = 0;
        }
        let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

        let remote = DummyIdentity::new([0xAB; 32]);
        let pairwise = PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
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

        let engine = CryptoEngine::new(DummyAes, DummySha);
        let blind_keys = engine.derive_blind_keys(&pairwise, &channel_keys);
        let mut buf = [0u8; 256];
        let builder = PacketBuilder::new(&mut buf)
            .blind_unicast(
                channel_keys.channel_id,
                umsh_core::NodeHint([0x77, 0x66, 0x55]),
            )
            .source_full(remote.public_key())
            .frame_counter(13)
            .flood_hops(3);
        let builder = if ack_requested {
            builder.ack_requested()
        } else {
            builder
        };
        let mut packet = builder.payload(b"ping").build().unwrap();
        engine
            .seal_blind_packet(&mut packet, &blind_keys, &channel_keys)
            .unwrap();

        mac.radio_mut().queue_received_frame(packet.as_bytes());
        let now_ms = mac.clock().now_ms();
        let guard_ms = u64::from(mac.radio_mut().t_frame_ms())
            * u64::from(mac.repeater_config().flood_contention_ack_guard_percent)
            / 100;
        assert!(guard_ms > 0);

        let handled = block_on(mac.receive_one(|_, _| {})).unwrap();
        assert!(handled);
        let forwarded = mac.tx_queue_mut().pop_next().unwrap();
        assert_eq!(forwarded.priority, TxPriority::Forward);
        if ack_requested {
            assert_eq!(forwarded.not_before_ms, now_ms + guard_ms);
        } else {
            assert_eq!(forwarded.not_before_ms, now_ms);
        }
    }
}

/// A device that shares its antenna with an attached host's stack sees
/// that stack's transmissions. Repeating one would put a frame back on
/// the air that this very antenna already sent, and the source address
/// is the host's, so the locally-originated check cannot catch it.
#[test]
fn repeater_does_not_repeat_what_its_own_antenna_transmitted() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().rx_origin = RxOrigin::LocalTx;
    mac.radio_mut().queue_received_frame(beacon.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a frame this antenna already sent was repeated"
    );

    // A neighbor's repeat of that same frame arrives moments later. The
    // frame has been on the air from here once already, which is what
    // the seeded duplicate entry remembers.
    mac.radio_mut().rx_origin = RxOrigin::Air;
    mac.radio_mut().queue_received_frame(beacon.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a repeat of an already-aired frame was forwarded"
    );
}

/// A frame handed over a backhaul link is a frame nobody else heard, so
/// it is the repeater's alone to carry — and it arrived with nothing
/// measured, which the signal gates and the trace must both respect.
#[test]
fn repeater_forwards_a_backhauled_frame_without_inventing_measurements() {
    let mut mac = make_mac();
    {
        let repeater = mac.repeater_config_mut();
        repeater.enabled = true;
        // Thresholds no wired frame could satisfy if they were applied.
        repeater.min_rssi = Some(-50);
        repeater.min_snr = Some(5);
    }
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .trace_signal()
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().rx_origin = RxOrigin::Backhaul;
    mac.radio_mut().queue_received_frame(beacon.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    let forwarded = mac
        .tx_queue_mut()
        .pop_next()
        .expect("a backhauled frame is the repeater's to carry");
    // Nobody else heard it, so there is no contention to stagger.
    assert_eq!(forwarded.not_before_ms, mac.clock().now_ms());

    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let options =
        ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone()).unwrap();
    let signal = options
        .trace_signal
        .expect("the hop still owes the trace an entry");
    assert_eq!(
        &forwarded.frame[signal][..2],
        &TraceSignalEntry::UNMEASURED.as_bytes(),
        "a wired hop must not publish a reading it never took"
    );
}

/// A beacon carries no body and no MIC, so every repetition from a node
/// hashes to the same duplicate key. Without an expiry the first one a
/// repeater forwards would be the last one it ever forwards.
#[test]
fn repeater_forwards_a_repeated_beacon_again_once_the_duplicate_entry_ages_out() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert!(
        mac.tx_queue_mut().pop_next().is_some(),
        "the first sighting of a beacon is forwarded"
    );

    // The identical beacon inside the window is a repeat of one packet.
    mac.radio_mut().queue_received_frame(beacon.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a repeat inside the suppression window is not forwarded again"
    );

    mac.clock().advance_ms(crate::cache::DUP_CACHE_TTL_MS);

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert!(
        mac.tx_queue_mut().pop_next().is_some(),
        "the node is heard again once its entry has aged out"
    );
}

/// A destination re-acks on purpose when the sender retransmits, and the
/// re-ack is byte-identical. The ack's dup entry ages out on the short
/// ack clock so that deliberate duplicate is carried, not absorbed.
#[test]
fn repeater_forwards_an_identical_reack_once_the_ack_entry_ages_out() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let mut buf = [0u8; 64];
    let ack = PacketBuilder::new(&mut buf)
        .mac_ack([0xA5; 8])
        .flood_hops(2)
        .build()
        .unwrap();
    let ack: heapless::Vec<u8, 64> = ack.iter().copied().collect();

    mac.radio_mut().queue_received_frame(ack.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert!(
        mac.tx_queue_mut().pop_next().is_some(),
        "the first sighting of the ack is forwarded"
    );

    // The same ack inside the window: flood copies of one transmission.
    mac.radio_mut().queue_received_frame(ack.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a copy inside the suppression window is not forwarded again"
    );

    mac.clock().advance_ms(crate::cache::ACK_DUP_CACHE_TTL_MS);

    mac.radio_mut().queue_received_frame(ack.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert!(
        mac.tx_queue_mut().pop_next().is_some(),
        "a re-ack after the ack window is carried onward"
    );
}

/// Queue a flooded beacon at a chosen signal level and report the contention
/// delay the repeater scheduled it with, relative to the clock.
fn flood_contention_delay_at(rssi_dbm: i16, snr: Snr) -> u64 {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.radio_mut().rx_rssi = rssi_dbm;
    mac.radio_mut().rx_snr = snr;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    forwarded.not_before_ms.saturating_sub(mac.clock().now_ms())
}

/// `W = W_min + (W_max − W_min) × max(1 − quality, signal)` (channel-access.md
/// § Flood Forwarding Contention). Two receptions demodulated equally cleanly
/// are separated by how loud they were: the faint one covers ground the
/// previous hop did not, so it goes first.
#[test]
fn flood_contention_makes_a_loud_reception_wait_longer_than_a_faint_one() {
    let clean = Snr::from_decibels(10);
    let faint = flood_contention_delay_at(-95, clean);
    let loud = flood_contention_delay_at(-50, clean);

    assert!(
        faint < loud,
        "faint {faint} ms should precede loud {loud} ms at equal quality"
    );
}

/// Either term alone can push the window to its maximum: a reception that is
/// barely demodulable waits as long as one that arrives on top of the sender.
#[test]
fn flood_contention_saturates_at_either_extreme() {
    // T_frame is 100 ms, so W_max is 50 ms and the jitter spans 10 ms.
    let noisy_and_faint = flood_contention_delay_at(-120, Snr::from_decibels(-20));
    let clean_and_loud = flood_contention_delay_at(-20, Snr::from_decibels(20));

    for delay in [noisy_and_faint, clean_and_loud] {
        assert!(
            (50..=60).contains(&delay),
            "{delay} ms should sit at W_max plus jitter"
        );
    }
}

/// With both window bounds collapsed the delay is jitter and nothing else,
/// which is what keeps repeaters that measured a reception identically from
/// transmitting in the same instant.
#[test]
fn flood_contention_leaves_only_jitter_when_the_window_is_collapsed() {
    let mut mac = make_mac();
    {
        let repeater = mac.repeater_config_mut();
        repeater.enabled = true;
        repeater.flood_contention_min_window_percent = 0;
        repeater.flood_contention_max_window_percent = 0;
    }
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let delay = forwarded.not_before_ms.saturating_sub(mac.clock().now_ms());

    assert!(
        (0..=10).contains(&delay),
        "{delay} ms should be jitter only"
    );
}

/// Trace signal is only useful if entry N lines up with trace-route hint N,
/// so a repeater that prepends a router hint must prepend its reading in the
/// same pass (packet-options.md § Trace Signal).
#[test]
fn repeater_prepends_its_signal_reading_alongside_the_router_hint() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.radio_mut().rx_rssi = -93;
    mac.radio_mut().rx_snr = Snr::from_centibels(-45);
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .trace_route()
        .trace_signal()
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();

    let frame = forwarded.frame.as_slice();
    let header = PacketHeader::parse(frame).unwrap();
    let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();
    let hint = &frame[options.trace_route.clone().unwrap()];
    let signal = &frame[options.trace_signal.clone().unwrap()];

    assert_eq!(hint.len(), 2, "one hop means one router hint");
    assert_eq!(
        signal,
        // -93 dBm carried as its magnitude, -4.5 dB as -45 centibels.
        &[93u8, (-45i8) as u8],
        "the reading is prepended as negative RSSI then signed centibel SNR"
    );
}

/// The same pairing on the path a ping actually takes. A unicast is forwarded
/// through the same rewrite as a beacon, and this pins that: an echo request
/// carries both options, so a repeater that grows only the route reports a
/// path whose per-hop cost is unreadable.
#[test]
fn repeater_prepends_its_signal_reading_when_forwarding_a_unicast() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.radio_mut().rx_rssi = -101;
    mac.radio_mut().rx_snr = Snr::from_centibels(35);
    let repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let repeater_hint = mac
        .identity(repeater_id)
        .unwrap()
        .identity()
        .public_key()
        .router_hint();

    // Addressed to somebody else, so this node forwards rather than consumes.
    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let dst = umsh_core::NodeHint([0x77, 0x66, 0x55]);
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(dst)
        .source_full(remote.public_key())
        .frame_counter(7)
        .encrypted()
        .flood_hops(3)
        .trace_route()
        .trace_signal()
        .payload(b"ping")
        .build()
        .unwrap();
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys)
        .unwrap();
    mac.radio_mut().queue_received_frame(packet.as_bytes());

    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let forwarded = mac.tx_queue_mut().pop_next().expect("forwarded unicast");

    let frame = forwarded.frame.as_slice();
    let header = PacketHeader::parse(frame).unwrap();
    let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();

    assert_eq!(
        &frame[options.trace_route.clone().unwrap()],
        &repeater_hint.0
    );
    assert_eq!(
        &frame[options.trace_signal.clone().unwrap()],
        &[101u8, 35u8],
        "one hint means one signal entry, prepended in the same pass"
    );
}

/// A reading past what one byte each can carry has to land on the nearest
/// representable value: a wrapped byte would read as a strong signal.
#[test]
fn trace_signal_saturates_rather_than_wrapping() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.radio_mut().rx_rssi = -300;
    mac.radio_mut().rx_snr = Snr::from_centibels(-2000);
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .trace_route()
        .trace_signal()
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();

    let frame = forwarded.frame.as_slice();
    let header = PacketHeader::parse(frame).unwrap();
    let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();
    let signal = &frame[options.trace_signal.clone().unwrap()];

    assert_eq!(signal, &[255u8, (-128i8) as u8]);
}

/// A trace accumulated past what this repeater can extend is over-limit
/// input from the air. The forward is declined — quietly, like any other
/// rewrite that will not fit — rather than trusted as a buffer index.
#[test]
fn repeater_declines_to_forward_an_overgrown_trace_rather_than_panicking() {
    for option in [OptionNumber::TraceRoute, OptionNumber::TraceSignal] {
        let mut mac = make_mac();
        mac.repeater_config_mut().enabled = true;
        let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

        let source = DummyIdentity::new([0xAB; 32]);
        let mut buf = [0u8; 256];
        let oversized = [0x22u8; crate::MAX_SOURCE_ROUTE_HOPS * 2 + 2];
        let beacon = PacketBuilder::new(&mut buf)
            .broadcast()
            .source_full(source.public_key())
            .flood_hops(3)
            .option(option, &oversized)
            .build()
            .unwrap();
        let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

        mac.radio_mut().queue_received_frame(beacon.as_slice());
        assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
        assert!(
            mac.tx_queue_mut().pop_next().is_none(),
            "an overgrown {option:?} drops the forward instead"
        );
    }
}

/// A frame that asked for neither trace option must not grow one: the
/// repeater reports the path it was asked about, and nothing else.
#[test]
fn repeater_does_not_add_trace_signal_to_a_frame_that_carries_no_trace() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let source = DummyIdentity::new([0xAB; 32]);
    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(source.public_key())
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    let forwarded = mac.tx_queue_mut().pop_next().unwrap();

    let frame = forwarded.frame.as_slice();
    let header = PacketHeader::parse(frame).unwrap();
    let options = ParsedOptions::extract(frame, header.options_range.clone()).unwrap();
    assert!(options.trace_signal.is_none());
    assert!(options.trace_route.is_none());
}

/// Hearing our own broadcast — off a repeater, off a reflection, off our own
/// receiver during a post-TX listen — must not put it back on the air. The
/// forwarding rewrite would prepend our router hint to the trace route,
/// teaching the destination a return path that begins by routing back through
/// the sender.
#[test]
fn repeater_does_not_forward_a_broadcast_it_originated() {
    let local = DummyIdentity::new([0x10; 32]);
    let local_key = *local.public_key();
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.add_identity(local).unwrap();

    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_full(&local_key)
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a repeater must not relay its own transmission"
    );
}

/// The 3-byte hint form hides nothing useful here: it is derived from the
/// public key, so our own hint identifies us just as well as our own key.
#[test]
fn repeater_does_not_forward_its_own_broadcast_sent_by_hint() {
    let local = DummyIdentity::new([0x10; 32]);
    let local_hint = local.public_key().hint();
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.add_identity(local).unwrap();

    let mut buf = [0u8; 256];
    let beacon = PacketBuilder::new(&mut buf)
        .broadcast()
        .source_hint(local_hint)
        .flood_hops(3)
        .build()
        .unwrap();
    let beacon: heapless::Vec<u8, 256> = beacon.iter().copied().collect();

    mac.radio_mut().queue_received_frame(beacon.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a repeater must not relay its own transmission"
    );
}

/// A packet addressed to us has arrived. Failing to decrypt it does not turn it
/// back into transit traffic.
#[test]
fn repeater_does_not_forward_a_unicast_addressed_to_itself() {
    let local = DummyIdentity::new([0x10; 32]);
    let local_hint = local.public_key().hint();
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.add_identity(local).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    // No pairwise keys installed, so the MAC cannot open it.
    let frame = build_received_unicast_frame(
        &remote,
        &keys,
        &local_hint,
        b"hello",
        false,
        Some((3, 0)),
        None,
        None,
    );

    mac.radio_mut().queue_received_frame(frame.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "a packet naming us as its destination has already arrived"
    );
}

#[test]
fn receive_one_repeater_inserts_region_on_untagged_flood_forward() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.repeater_config_mut()
        .regions
        .push([0x78, 0x53])
        .unwrap();
    mac.repeater_config_mut().default_region = Some([0x78, 0x53]);
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let frame = build_received_unicast_frame(
        &remote,
        &keys,
        &umsh_core::NodeHint([0x77, 0x66, 0x55]),
        b"hello",
        false,
        Some((4, 1)),
        None,
        None,
    );

    mac.radio_mut().queue_received_frame(frame.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let options =
        ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone()).unwrap();

    assert_eq!(options.region_code, Some([0x78, 0x53]));
    assert_eq!(header.flood_hops.unwrap(), FloodHops::new(3, 2).unwrap());
}

/// Flood-forward an untagged unicast through a repeater configured with
/// `regions` but the supplied `default_region`, and report the region code
/// carried by the forwarded frame.
fn forwarded_region_for_untagged_flood(
    regions: &[[u8; 2]],
    default_region: Option<[u8; 2]>,
) -> Option<[u8; 2]> {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    for region in regions {
        mac.repeater_config_mut().regions.push(*region).unwrap();
    }
    mac.repeater_config_mut().default_region = default_region;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let frame = build_received_unicast_frame(
        &remote,
        &keys,
        &umsh_core::NodeHint([0x77, 0x66, 0x55]),
        b"hello",
        false,
        Some((4, 1)),
        None,
        None,
    );

    mac.radio_mut().queue_received_frame(frame.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone())
        .unwrap()
        .region_code
}

#[test]
fn receive_one_repeater_leaves_untagged_flood_untagged_without_a_default_region() {
    assert_eq!(
        forwarded_region_for_untagged_flood(&[[0x78, 0x53]], None),
        None,
        "a configured region list must not imply a default region to insert"
    );
}

#[test]
fn receive_one_repeater_inserts_the_default_region_not_the_first_configured_one() {
    assert_eq!(
        forwarded_region_for_untagged_flood(&[[0x31, 0xD9], [0x78, 0x53]], Some([0x78, 0x53])),
        Some([0x78, 0x53])
    );
    // The default region need not appear in the filter list at all.
    assert_eq!(
        forwarded_region_for_untagged_flood(&[[0x31, 0xD9]], Some([0xAB, 0xCD])),
        Some([0xAB, 0xCD])
    );
}

#[test]
fn receive_one_repeater_without_configured_regions_forwards_tagged_floods() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(umsh_core::NodeHint([0x77, 0x66, 0x55]))
        .source_full(remote.public_key())
        .frame_counter(7)
        .encrypted()
        .flood_hops(4)
        .region_code([0x78, 0x53])
        .payload(b"hello")
        .build()
        .unwrap();
    {
        packet.header().unwrap();
        packet.as_bytes_mut()[1] = FloodHops::new(4, 0).unwrap().0;
    }
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys)
        .unwrap();

    mac.radio_mut().queue_received_frame(packet.as_bytes());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let forwarded = mac.tx_queue_mut().pop_next().expect(
        "an empty region list imposes no regional restriction, so a tagged \
         flood packet must still be forwarded",
    );
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let options =
        ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone()).unwrap();
    assert_eq!(options.region_code, Some([0x78, 0x53]));
}

#[test]
fn receive_one_repeater_preserves_existing_region_without_inserting_another() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.repeater_config_mut()
        .regions
        .push([0x31, 0xD9])
        .unwrap();
    mac.repeater_config_mut()
        .regions
        .push([0x78, 0x53])
        .unwrap();
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(umsh_core::NodeHint([0x77, 0x66, 0x55]))
        .source_full(remote.public_key())
        .frame_counter(7)
        .encrypted()
        .flood_hops(4)
        .region_code([0x78, 0x53])
        .payload(b"hello")
        .build()
        .unwrap();
    {
        packet.header().unwrap();
        packet.as_bytes_mut()[1] = FloodHops::new(4, 0).unwrap().0;
    }
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys)
        .unwrap();

    mac.radio_mut().queue_received_frame(packet.as_bytes());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let options =
        ParsedOptions::extract(forwarded.frame.as_slice(), header.options_range.clone()).unwrap();
    let region_occurrences = iter_options(forwarded.frame.as_slice(), header.options_range.clone())
        .filter_map(Result::ok)
        .filter(|(number, _)| OptionNumber::from(*number) == OptionNumber::RegionCode)
        .count();

    assert_eq!(options.region_code, Some([0x78, 0x53]));
    assert_eq!(region_occurrences, 1);
}

#[test]
fn receive_one_repeater_accepts_any_matching_region_from_multiple_region_options() {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    mac.repeater_config_mut()
        .regions
        .push([0x78, 0x53])
        .unwrap();
    let _repeater_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();

    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(umsh_core::NodeHint([0x77, 0x66, 0x55]))
        .source_full(remote.public_key())
        .frame_counter(7)
        .encrypted()
        .flood_hops(4)
        .option(OptionNumber::RegionCode, &[0x31, 0xD9])
        .option(OptionNumber::RegionCode, &[0x78, 0x53])
        .payload(b"hello")
        .build()
        .unwrap();
    {
        packet.header().unwrap();
        packet.as_bytes_mut()[1] = FloodHops::new(4, 0).unwrap().0;
    }
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys)
        .unwrap();

    mac.radio_mut().queue_received_frame(packet.as_bytes());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    let forwarded = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(forwarded.frame.as_slice()).unwrap();
    let region_occurrences = iter_options(forwarded.frame.as_slice(), header.options_range.clone())
        .filter_map(Result::ok)
        .filter(|(number, _)| OptionNumber::from(*number) == OptionNumber::RegionCode)
        .count();

    assert_eq!(region_occurrences, 2);
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
fn counters_tally_every_transmission_including_forwards() {
    let mut mac = make_mac();
    assert_eq!(mac.counters(), crate::MacCounters::default());

    // No identity on these, which is what a forwarded frame looks like:
    // they emit no event, so only the counter can see them.
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", None, None)
        .unwrap();
    mac.tx_queue_mut()
        .enqueue(TxPriority::Retry, b"retry", Some(SendReceipt(7)), None)
        .unwrap();
    block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();

    assert_eq!(mac.counters().tx_frames, 2);
    assert_eq!(mac.counters().tx_abandoned, 0);
}

#[test]
fn counters_record_a_frame_abandoned_to_a_busy_channel() {
    let mut mac = make_mac();
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        mac.radio_mut().cad_responses.push_back(true).unwrap();
    }
    mac.tx_queue_mut()
        .enqueue(TxPriority::Application, b"app", None, None)
        .unwrap();

    // Each busy CAD requeues with a backoff, so the queue has to be
    // drained repeatedly to walk the frame through its attempts.
    for _ in 0..crate::MAX_CAD_ATTEMPTS {
        block_on(mac.drain_tx_queue(&mut |_, _| {})).unwrap();
        mac.clock().advance_ms(60_000);
    }

    assert!(mac.radio().transmitted.is_empty());
    assert_eq!(mac.counters().tx_frames, 0);
    assert_eq!(mac.counters().tx_abandoned, 1);
    assert!(mac.tx_queue().is_empty());
}

/// A node hearing traffic it cannot use still counts the reception. The
/// gap between the two numbers is the whole point: it is what tells a
/// deaf radio (`rx_frames` flat) apart from a busy neighbourhood
/// (`rx_frames` climbing, `rx_accepted` not).
#[test]
fn counters_separate_receptions_from_receptions_that_meant_something() {
    let mut mac = make_mac();
    mac.radio_mut().queue_received_frame(b"not a umsh frame");
    let handled = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(!handled);
    assert_eq!(mac.counters().rx_frames, 1);
    assert_eq!(mac.counters().rx_accepted, 0);
    assert_eq!(mac.counters().forwarded, 0);
}

#[test]
fn counters_record_a_forwarded_frame() {
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
    let source_route = [repeater_hint, RouterHint([0x21, 0x22])];
    let original = build_received_blind_unicast_frame(
        &remote,
        &pairwise,
        &channel_keys,
        &umsh_core::NodeHint([0x77, 0x66, 0x55]),
        b"hello",
        false,
        Some(&source_route),
    );
    mac.radio_mut().queue_received_frame(original.as_slice());

    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.counters().rx_frames, 1);
    assert_eq!(mac.counters().rx_accepted, 1);
    assert_eq!(mac.counters().forwarded, 1);
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
            cad: umsh_hal::CadPolicy::Gate,
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
    assert!(matches!(
        poll_radio_once(&mut carol, &mut buf),
        Poll::Pending
    ));

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
    assert!(matches!(
        poll_radio_once(&mut dave, &mut buf),
        Poll::Pending
    ));
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
                &SendOptions::default().with_flood_hops(8).with_trace_route(),
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
                if let MacEventRef::AckTimeout {
                    receipt: timed_out, ..
                } = event
                {
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
fn modeled_parallel_paths_prefer_reaching_branch_for_route_learning() {
    // Diamond topology:
    // Alice -> reaching -> Bob
    // Alice -> crowding -> Bob
    //
    // Both branches hear Alice cleanly, but the crowding one sits close enough
    // that its forward would mostly re-cover Alice's own footprint, so it waits.
    // The initial flooded packet arrives either way; the trace route Bob learns
    // back to Alice should follow the branch that transmitted first.
    let mut scenario = build_modeled_line_scenario(4);
    let alice = 0usize;
    let reaching = 1usize;
    let crowding = 2usize;
    let bob = 3usize;
    install_pairwise_keys_between(&mut scenario, alice, bob);

    disconnect_modeled_bidirectional(
        &scenario.network,
        scenario.radio_ids[reaching],
        scenario.radio_ids[crowding],
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[alice],
        scenario.radio_ids[reaching],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -92,
            base_snr: Snr::from_decibels(6),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[reaching],
        scenario.radio_ids[bob],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -90,
            base_snr: Snr::from_decibels(6),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[alice],
        scenario.radio_ids[crowding],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -55,
            base_snr: Snr::from_decibels(15),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[crowding],
        scenario.radio_ids[bob],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -55,
            base_snr: Snr::from_decibels(15),
            rssi_jitter_dbm: 0,
            snr_jitter_centibels: 0,
            propagation_delay_ms: 2,
            drop_per_thousand: 0,
        },
    );
    connect_modeled_bidirectional_with_profile(
        &scenario.network,
        scenario.radio_ids[reaching],
        scenario.radio_ids[crowding],
        crate::test_support::ModeledLinkProfile {
            connected: true,
            base_rssi: -70,
            base_snr: Snr::from_decibels(10),
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
        "bob should receive the initial packet across the reaching branch",
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
    let reaching_hint = scenario.macs[reaching]
        .borrow()
        .identity(scenario.identity_ids[reaching])
        .unwrap()
        .identity()
        .public_key()
        .router_hint();
    assert_eq!(
        learned_route,
        Some(CachedRoute::Source(
            heapless::Vec::from_slice(&[reaching_hint]).unwrap()
        ))
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
    // Alice and Bob have four candidate relays between them. Two hear Alice
    // cleanly but faintly — the ones whose forward covers new ground — and two
    // sit right on top of her, loud enough that repeating buys little reach.
    // Flood learning should settle on one of the reaching pair.
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
            .add_identity(crate::test_support::DummyIdentity::new(
                [0x30u8.wrapping_add(index as u8); 32],
            ))
            .unwrap();
        identity_ids.push(id);
        keys.push(*mac.identity(id).unwrap().identity().public_key());
        macs.push(RefCell::new(mac));
    }

    for repeater in 1..=4 {
        let profile = if repeater <= 2 {
            // Clean and faint: full quality, little of the signal term.
            crate::test_support::ModeledLinkProfile {
                connected: true,
                base_rssi: -88,
                base_snr: Snr::from_decibels(8),
                rssi_jitter_dbm: 0,
                snr_jitter_centibels: 0,
                propagation_delay_ms: 2,
                drop_per_thousand: 0,
            }
        } else {
            // Clean and loud: the signal term saturates and the forward waits.
            crate::test_support::ModeledLinkProfile {
                connected: true,
                base_rssi: -55,
                base_snr: Snr::from_decibels(15),
                rssi_jitter_dbm: 0,
                snr_jitter_centibels: 0,
                propagation_delay_ms: 2,
                drop_per_thousand: 0,
            }
        };
        connect_modeled_bidirectional_with_profile(
            &network,
            radio_ids[0],
            radio_ids[repeater],
            profile,
        );
        connect_modeled_bidirectional_with_profile(
            &network,
            radio_ids[repeater],
            radio_ids[5],
            profile,
        );
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
        k_enc: [0x21; 32],
        k_mic: [0x42; 32],
    };
    {
        let mut alice_mac = macs[0].borrow_mut();
        let peer_id = alice_mac.add_peer(keys[5]).unwrap();
        alice_mac
            .install_pairwise_keys(identity_ids[0], peer_id, pairwise.clone())
            .unwrap();
    }
    {
        let mut bob_mac = macs[5].borrow_mut();
        let peer_id = bob_mac.add_peer(keys[0]).unwrap();
        bob_mac
            .install_pairwise_keys(identity_ids[5], peer_id, pairwise)
            .unwrap();
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
    // The route Bob learns from the *delivering* copy is what the contention
    // window decides. Later flood copies of the same packet keep arriving, and
    // one that lands outside the re-ack holdoff is re-acknowledged and teaches
    // its own path, so the registry read after the exchange settles reflects
    // whichever repeater forwarded last — not which one won the race.
    let delivering_trace = RefCell::new(None::<heapless::Vec<u8, 32>>);
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
                if bob_delivery.get() == 0 {
                    let trace = packet
                        .trace_route()
                        .and_then(|bytes| heapless::Vec::from_slice(bytes).ok())
                        .expect("the delivered copy carries its accumulated trace");
                    *delivering_trace.borrow_mut() = Some(trace);
                }
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
        "one of the reaching candidate repeaters should carry the first route-learning packet",
    );

    let (alice_peer_id, _) = macs[5]
        .borrow()
        .peer_registry()
        .lookup_by_key(&keys[0])
        .unwrap();
    let learned_route = macs[5]
        .borrow()
        .peer_registry()
        .get(alice_peer_id)
        .unwrap()
        .route
        .clone();
    let reaching_hints = [
        macs[1]
            .borrow()
            .identity(identity_ids[1])
            .unwrap()
            .identity()
            .public_key()
            .router_hint(),
        macs[2]
            .borrow()
            .identity(identity_ids[2])
            .unwrap()
            .identity()
            .public_key()
            .router_hint(),
    ];
    let delivering_trace = delivering_trace.borrow().clone().unwrap();
    let delivering_hint = RouterHint([delivering_trace[0], delivering_trace[1]]);
    assert_eq!(delivering_trace.len(), 2);
    assert!(
        reaching_hints.contains(&delivering_hint),
        "packet was delivered via {delivering_hint:?}, expected one of {reaching_hints:?}"
    );
    // Whichever copy taught it last, a one-hop route is all any of these
    // candidates can offer.
    assert!(matches!(
        learned_route,
        Some(CachedRoute::Source(route)) if route.len() == 1
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
                packet
                    .from_hint()
                    .expect("multicast source hint should be present")
                    .0,
                packet.payload_bytes().to_vec(),
            ));
        },
        || seen.borrow().len() == 2,
        "receiver should accept multicast from unknown senders without peer registration",
    );
    assert!(
        scenario.macs[receiver]
            .borrow()
            .peer_registry()
            .lookup_by_key(&scenario.keys[sender_a])
            .is_none()
    );
    assert!(
        scenario.macs[receiver]
            .borrow()
            .peer_registry()
            .lookup_by_key(&scenario.keys[sender_b])
            .is_none()
    );
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
                [payload_type, 4, ..]
                    if node_index == alice && *payload_type == PayloadType::MacCommand as u8 =>
                {
                    alice_echo_requests.set(alice_echo_requests.get() + 1);
                }
                [payload_type, 5, ..]
                    if node_index == bob && *payload_type == PayloadType::MacCommand as u8 =>
                {
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
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(4),
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
                &SendOptions::default()
                    .with_ack_requested(true)
                    .with_flood_hops(4),
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
        k_enc: [1; 32],
        k_mic: [2; 32],
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
        .ack_trailer;
    mac.radio_mut().queue_received_mac_ack(ack_tag);

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
        .ack_trailer;

    let _ = mac.tx_queue_mut().pop_next();
    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    mac.radio_mut().queue_received_mac_ack(ack_tag);

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
    let retry_options =
        ParsedOptions::extract(retry.frame.as_slice(), retry_header.options_range.clone()).unwrap();
    assert!(retry_options.route_retry);
    assert!(retry_options.trace_route.is_some());
    assert!(retry_options.source_route.is_none());
    assert_eq!(retry_header.flood_hops.unwrap().remaining(), 1);

    let original_header = PacketHeader::parse(original_frame.as_slice()).unwrap();
    assert_eq!(
        &retry.frame.as_slice()[retry_header.mic_range.clone()],
        &original_frame.as_slice()[original_header.mic_range.clone()]
    );

    let pending = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap();
    assert!(matches!(pending.state, AckState::RetryQueued));
    assert_eq!(pending.retries, 0);
    assert!(
        pending.ack_deadline_ms > mac.clock().now_ms(),
        "the rewritten attempt needs a live window while it waits in the queue"
    );
    assert!(pending.resend.source_route.is_none());
    let pending_header = PacketHeader::parse(pending.resend.frame.as_slice()).unwrap();
    let pending_options = ParsedOptions::extract(
        pending.resend.frame.as_slice(),
        pending_header.options_range.clone(),
    )
    .unwrap();
    assert!(pending_options.route_retry);
}

/// Send a flooded, ack-requested unicast and report how long the MAC will wait
/// for the acknowledgement.
fn forwarded_ack_window_for_flood_hops(flood_hops: u8) -> u64 {
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

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(flood_hops),
        )
        .unwrap()
        .unwrap();
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();

    let sent_ms = mac.clock().now_ms();
    mac.identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_deadline_ms
        .saturating_sub(sent_ms)
}

/// The retry ladder only measures the first hop, which is the only one this
/// node can watch. The rest of the wait is distance: an acknowledgement from
/// four hops away has eight forwarding delays to cross before it arrives, and
/// charging for them is what stops a delivery that actually worked from being
/// reported as a timeout.
#[test]
fn forwarded_ack_window_grows_with_the_hops_the_ack_must_cross() {
    let near = forwarded_ack_window_for_flood_hops(1);
    let far = forwarded_ack_window_for_flood_hops(4);

    assert!(
        far > near,
        "a four-hop flood ({far} ms) should be given longer than a one-hop one ({near} ms)"
    );
    // T_frame is 100 ms: the ladder is 2.85 + 3 × 3.85 = 14.4 frame times and
    // each further hop of round trip costs 2 × 1.85.
    assert_eq!(near, 1_440 + 2 * 185);
    assert_eq!(far, 1_440 + 8 * 185);
}

/// A route retry waits out a backoff in the transmit queue. The sweep that
/// scheduled it runs again in that window — and must not read the fresh
/// attempt as an expired one, which would report the send failed and pull the
/// retry back out of the queue before it ever aired.
#[test]
fn route_retry_survives_a_timeout_sweep_before_it_airs() {
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

    let mut route = heapless::Vec::new();
    route.push(RouterHint([1, 2])).unwrap();
    let mut options = SendOptions::default().with_ack_requested(true).no_flood();
    options.source_route = Some(route);

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    let _original = mac.tx_queue_mut().pop_next().unwrap();

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    assert_eq!(mac.tx_queue_mut().len(), 1);
    let now_ms = mac.clock().now_ms();
    assert!(
        !mac.tx_queue_mut().has_ready(now_ms),
        "this test only means something while the retry is still held back"
    );

    // The retry is eligible only later, so the wake-up scheduler must not be
    // pointed at a deadline that has already passed.
    assert!(
        mac.earliest_deadline_ms().unwrap() > mac.clock().now_ms(),
        "an already-expired deadline spins the loop straight back into the sweep"
    );

    let mut timeout_seen = false;
    mac.service_pending_ack_timeouts(|_, event| {
        if matches!(event, MacEventRef::AckTimeout { .. }) {
            timeout_seen = true;
        }
    })
    .unwrap();

    assert!(!timeout_seen, "the retry had not aired yet");
    assert_eq!(mac.tx_queue_mut().len(), 1, "the retry is still queued");
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_some(),
        "the ack trailer must stay correlatable or the ack cannot be matched"
    );
}

/// The rewritten attempt reuses the original's MIC verbatim, so every byte the
/// AAD covers has to survive the rewrite — including the FCF, whose
/// flood-hops-present bit flips when a source route is abandoned for a flood.
#[test]
fn route_retry_preserves_the_authenticated_header() {
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

    let mut route = heapless::Vec::new();
    route.push(RouterHint([1, 2])).unwrap();
    let mut options = SendOptions::default().with_ack_requested(true).no_flood();
    options.source_route = Some(route);

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &options)
        .unwrap()
        .unwrap();
    let original = mac.tx_queue_mut().pop_next().unwrap();

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    let retry = mac.tx_queue_mut().pop_next().unwrap();

    let collect_aad = |frame: &[u8]| {
        let header = PacketHeader::parse(frame).unwrap();
        let mut aad = std::vec::Vec::new();
        feed_aad(&header, frame, |chunk| aad.extend_from_slice(chunk));
        aad
    };

    assert_ne!(
        original.frame.as_slice()[0],
        retry.frame.as_slice()[0],
        "the rewrite is expected to add FHOPS, changing the FCF on the wire"
    );
    assert_eq!(
        collect_aad(original.frame.as_slice()),
        collect_aad(retry.frame.as_slice()),
        "the copied MIC only verifies if the AAD is byte-identical"
    );
}

/// A peer cached as directly reachable transmits at
/// `ESTABLISHED_ROUTE_EXTRA_HOPS` no matter how wide a flood the caller asked
/// for, and carries no option saying so. When it stops answering, the cache
/// entry is exactly as stale as a dead source-route hint — the retry has to
/// abandon it and flood at the budget the application actually requested.
#[test]
fn route_retry_escalates_a_send_narrowed_by_a_cached_direct_route() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(5),
        )
        .unwrap()
        .unwrap();

    let original = mac.tx_queue_mut().pop_next().unwrap();
    let original_header = PacketHeader::parse(original.frame.as_slice()).unwrap();
    let original_options = ParsedOptions::extract(
        original.frame.as_slice(),
        original_header.options_range.clone(),
    )
    .unwrap();
    assert_eq!(
        original_header.flood_hops.unwrap().remaining(),
        ESTABLISHED_ROUTE_EXTRA_HOPS,
        "a direct cache entry should narrow the attempt's budget"
    );
    assert!(
        original_options.source_route.is_none(),
        "the narrowing is recorded in FHOPS, not in an option"
    );

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    let mut timeout_seen = false;
    mac.service_pending_ack_timeouts(|_, event| {
        if matches!(event, MacEventRef::AckTimeout { .. }) {
            timeout_seen = true;
        }
    })
    .unwrap();
    assert!(!timeout_seen, "the send should be retried, not abandoned");

    let retry = mac.tx_queue_mut().pop_next().unwrap();
    let retry_header = PacketHeader::parse(retry.frame.as_slice()).unwrap();
    let retry_options =
        ParsedOptions::extract(retry.frame.as_slice(), retry_header.options_range.clone()).unwrap();
    assert!(retry_options.route_retry);
    assert!(
        retry_options.trace_route.is_some(),
        "the retry should ask for a replacement route"
    );
    assert_eq!(retry_header.flood_hops.unwrap().remaining(), 5);
    assert_eq!(
        &retry.frame.as_slice()[retry_header.mic_range.clone()],
        &original.frame.as_slice()[original_header.mic_range.clone()],
        "route retry re-sends the same logical packet"
    );
}

/// A caller that asked for a direct send gets a direct send. Route recovery
/// undoes the MAC's own narrowing; it does not overrule the application.
#[test]
fn route_retry_is_not_attempted_when_the_caller_chose_the_narrow_budget() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut()
        .update_route(peer_id, CachedRoute::Direct);

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true).no_flood(),
        )
        .unwrap()
        .unwrap();

    let original = mac.tx_queue_mut().pop_next().unwrap();
    let original_header = PacketHeader::parse(original.frame.as_slice()).unwrap();
    assert!(
        original_header.flood_hops.is_none(),
        "no_flood should leave the FHOPS byte off entirely"
    );

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    let mut timeout_seen = false;
    mac.service_pending_ack_timeouts(|_, event| {
        if matches!(event, MacEventRef::AckTimeout { .. }) {
            timeout_seen = true;
        }
    })
    .unwrap();

    assert!(timeout_seen, "a caller-chosen direct send should time out");
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "route retry must not invent a flood the caller declined"
    );
}

/// Nothing was narrowed, so there is no route assumption to abandon.
#[test]
fn route_retry_is_not_attempted_when_the_send_already_flooded_as_asked() {
    let (mut mac, local_id, peer_key, _peer_id) = mac_with_keyed_peer();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default()
                .with_ack_requested(true)
                .with_flood_hops(5),
        )
        .unwrap()
        .unwrap();

    let original = mac.tx_queue_mut().pop_next().unwrap();
    let original_header = PacketHeader::parse(original.frame.as_slice()).unwrap();
    assert_eq!(original_header.flood_hops.unwrap().remaining(), 5);

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;

    let mut timeout_seen = false;
    mac.service_pending_ack_timeouts(|_, event| {
        if matches!(event, MacEventRef::AckTimeout { .. }) {
            timeout_seen = true;
        }
    })
    .unwrap();

    assert!(timeout_seen);
    assert!(mac.tx_queue_mut().pop_next().is_none());
}

#[test]
fn route_retry_restores_the_full_budget_after_a_narrowed_source_routed_send() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Source(
            heapless::Vec::from_slice(&[RouterHint([1, 2]), RouterHint([3, 4])]).unwrap(),
        ),
    );

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_ack_requested(true),
        )
        .unwrap()
        .unwrap();

    let original = mac.tx_queue_mut().pop_next().unwrap();
    let original_header = PacketHeader::parse(original.frame.as_slice()).unwrap();
    assert_eq!(
        original_header.flood_hops.unwrap().remaining(),
        ESTABLISHED_ROUTE_EXTRA_HOPS,
        "the cached route should narrow the attempt's budget"
    );

    let pending = mac
        .identity_mut(local_id)
        .unwrap()
        .pending_ack_mut(&receipt)
        .unwrap();
    pending.state = AckState::AwaitingAck;
    pending.ack_deadline_ms = 0;
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();

    // The route just failed, so rediscovery must flood as widely as the
    // application originally allowed rather than inherit the narrowed budget.
    let retry = mac.tx_queue_mut().pop_next().unwrap();
    let retry_header = PacketHeader::parse(retry.frame.as_slice()).unwrap();
    let retry_options =
        ParsedOptions::extract(retry.frame.as_slice(), retry_header.options_range.clone()).unwrap();
    assert!(retry_options.route_retry);
    assert_eq!(retry_header.flood_hops.unwrap().remaining(), 5);
}

#[test]
fn queued_retry_does_not_rearm_forward_confirmation_before_retransmit() {
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
        .ack_trailer;

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

/// Build a sealed pass-through UNAR (someone else's traffic) for repeater
/// tests: full source, arbitrary destination hint, 3 flood hops.
fn build_passing_unar(route_retry: bool) -> heapless::Vec<u8, 256> {
    let remote = DummyIdentity::new([0xAB; 32]);
    let keys = PairwiseKeys {
        k_enc: [3; 32],
        k_mic: [4; 32],
    };
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf)
        .unicast(NodeHint([0x77, 0x66, 0x55]))
        .source_full(remote.public_key())
        .frame_counter(13)
        .ack_requested()
        .encrypted()
        .mic_size(umsh_core::MicSize::Mic16)
        .flood_hops(3);
    let builder = if route_retry {
        builder.option(OptionNumber::RouteRetry, &[])
    } else {
        builder
    };
    let mut packet = builder.payload(b"ping").build().unwrap();
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut packet, &keys)
        .unwrap();
    let mut stored: heapless::Vec<u8, 256> = heapless::Vec::new();
    stored.extend_from_slice(packet.as_bytes()).unwrap();
    stored
}

fn mic_prefix(frame: &[u8]) -> [u8; 4] {
    let header = PacketHeader::parse(frame).unwrap();
    let mic = &frame[header.mic_range.clone()];
    [mic[0], mic[1], mic[2], mic[3]]
}

fn make_repeater_mac() -> TestMac {
    let mut mac = make_mac();
    mac.repeater_config_mut().enabled = true;
    let _ = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac
}

#[test]
fn overheard_mac_ack_cancels_matching_queued_forward() {
    let mut mac = make_repeater_mac();
    let unar = build_passing_unar(false);

    mac.radio_mut().queue_received_frame(unar.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    // The destination's ack: the public MIC prefix, an unverifiable tag.
    let prefix = mic_prefix(unar.as_slice());
    let mut trailer = [0u8; 8];
    trailer[..4].copy_from_slice(&prefix);
    trailer[4..].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    mac.radio_mut().queue_received_mac_ack(trailer);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(
        mac.tx_queue().is_empty(),
        "the acknowledged forward is withdrawn"
    );
    assert_eq!(mac.counters().forward_cancelled, 1);

    // The cancellation leaves the duplicate entry in place: another copy of
    // the same attempt arriving later is not re-queued.
    mac.radio_mut().queue_received_frame(unar.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(mac.tx_queue().is_empty());
}

#[test]
fn overheard_mac_ack_cancels_a_route_retry_copy_too() {
    let mut mac = make_repeater_mac();
    let retry_copy = build_passing_unar(true);

    mac.radio_mut().queue_received_frame(retry_copy.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    let prefix = mic_prefix(retry_copy.as_slice());
    let mut trailer = [0u8; 8];
    trailer[..4].copy_from_slice(&prefix);
    mac.radio_mut().queue_received_mac_ack(trailer);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(mac.tx_queue().is_empty());
}

/// Cancellation is an event on the queue, not a standing verdict: a
/// route-retry copy arriving *after* the original was cancelled is a fresh
/// forwarding identity — the origin resorted to it because the ack never
/// reached it — and must be carried, and is in turn cancelable.
#[test]
fn cancellation_does_not_suppress_a_later_route_retry_copy() {
    let mut mac = make_repeater_mac();
    let original = build_passing_unar(false);
    let retry_copy = build_passing_unar(true);

    mac.radio_mut().queue_received_frame(original.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    let prefix = mic_prefix(original.as_slice());
    let mut trailer = [0u8; 8];
    trailer[..4].copy_from_slice(&prefix);
    mac.radio_mut().queue_received_mac_ack(trailer);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(mac.tx_queue().is_empty());

    // Same MIC, distinct forwarding identity: queued and forwarded.
    mac.radio_mut().queue_received_frame(retry_copy.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    // And another overheard ack takes it back out.
    mac.radio_mut().queue_received_mac_ack(trailer);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.counters().forward_cancelled, 2);
}

#[test]
fn unrelated_mac_ack_leaves_a_queued_forward_alone() {
    let mut mac = make_repeater_mac();
    let unar = build_passing_unar(false);

    mac.radio_mut().queue_received_frame(unar.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    mac.radio_mut()
        .queue_received_mac_ack([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert_eq!(mac.tx_queue().len(), 1);
    assert_eq!(mac.counters().forward_cancelled, 0);
}

/// A MAC ack's own trailer opens with the same four bytes it echoes, so a
/// second copy of the ack must not cancel the queued forward of the ack
/// itself — only the acknowledged data packet's forward is fair game.
#[test]
fn duplicate_mac_ack_does_not_cancel_the_queued_ack_forward() {
    let mut mac = make_repeater_mac();
    let trailer = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut buf = [0u8; 256];
    let ack = PacketBuilder::new(&mut buf)
        .mac_ack(trailer)
        .flood_hops(3)
        .build()
        .unwrap();
    let ack: heapless::Vec<u8, 256> = ack.iter().copied().collect();

    mac.radio_mut().queue_received_frame(ack.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    mac.radio_mut().queue_received_frame(ack.as_slice());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert_eq!(mac.tx_queue().len(), 1, "the ack forward survives");
    let queued = mac.tx_queue_mut().pop_next().unwrap();
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert_eq!(header.packet_type(), PacketType::MacAck);
    assert_eq!(mac.counters().forward_cancelled, 0);
}

/// The Ack MIC option is the piggy-backed form of the same evidence: a data
/// packet travelling the other way names the acknowledged packet's MIC
/// prefix, and a forwarder holding that packet reads it without any keys.
#[test]
fn ack_mic_option_cancels_matching_queued_forward() {
    let mut mac = make_repeater_mac();
    let unar = build_passing_unar(false);

    mac.radio_mut().queue_received_frame(unar.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());
    assert_eq!(mac.tx_queue().len(), 1);

    // A reply the repeater cannot decrypt, carrying the Ack MIC option.
    let prefix = mic_prefix(unar.as_slice());
    let replier = DummyIdentity::new([0xCD; 32]);
    let reply_keys = PairwiseKeys {
        k_enc: [5; 32],
        k_mic: [6; 32],
    };
    let mut buf = [0u8; 256];
    let mut reply = PacketBuilder::new(&mut buf)
        .unicast(NodeHint([0x44, 0x33, 0x22]))
        .source_full(replier.public_key())
        .frame_counter(2)
        .encrypted()
        .mic_size(umsh_core::MicSize::Mic16)
        .option(OptionNumber::AckMic, &prefix)
        .payload(b"reply")
        .build()
        .unwrap();
    CryptoEngine::new(DummyAes, DummySha)
        .seal_packet(&mut reply, &reply_keys)
        .unwrap();
    mac.radio_mut().queue_received_frame(reply.as_bytes());
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();

    assert!(mac.tx_queue().is_empty());
    assert_eq!(mac.counters().forward_cancelled, 1);
}

/// Install identity + peer + pairwise keys; the boilerplate every sender-side
/// tracking test starts from.
fn make_sender_mac() -> (TestMac, LocalIdentityId, PublicKey) {
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

fn sole_tracked_receipt(mac: &TestMac, local_id: LocalIdentityId) -> SendReceipt {
    let slot = mac.identity(local_id).unwrap();
    let mut entries = slot.pending_acks();
    let (receipt, _) = entries.next().expect("a tracked send");
    assert!(entries.next().is_none(), "exactly one tracked send");
    *receipt
}

/// A non-ACK unicast with a flood budget is tracked internally (no receipt
/// for the caller) and walks the full retry ladder when no repeat is ever
/// heard, ending in silence: no AckTimeout, no retry left behind.
#[test]
fn non_ack_unicast_with_hops_retries_until_the_ladder_ends() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

    let receipt = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default())
        .unwrap();
    assert!(receipt.is_none(), "no receipt for a non-ACK send");
    let receipt = sole_tracked_receipt(&mac, local_id);
    assert!(
        !mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .unwrap()
            .expects_ack()
    );

    let mut timeouts = 0u32;
    let mut on_event = |_: LocalIdentityId, event: MacEventRef<'_>| {
        if matches!(event, MacEventRef::AckTimeout { .. }) {
            timeouts += 1;
        }
    };

    let _ = block_on(mac.transmit_next(&mut on_event)).unwrap();
    assert_eq!(mac.radio().transmitted.len(), 1);

    let t_frame = u64::from(mac.radio_mut().t_frame_ms());
    for expected_tx in 2..=(1 + u64::from(crate::MAX_FORWARD_RETRIES)) {
        let confirm_deadline_ms = match mac
            .identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .unwrap()
            .state
        {
            AckState::AwaitingForward {
                confirm_deadline_ms,
            } => confirm_deadline_ms,
            other => panic!("expected AwaitingForward, got {other:?}"),
        };
        mac.clock()
            .advance_ms(confirm_deadline_ms.saturating_sub(mac.clock().now_ms()));
        mac.service_pending_ack_timeouts(&mut on_event).unwrap();
        assert_eq!(mac.tx_queue().len(), 1, "a retry is queued");
        // The retry jitter is flat: at most one frame time.
        mac.clock().advance_ms(t_frame + 1);
        let _ = block_on(mac.transmit_next(&mut on_event)).unwrap();
        assert_eq!(mac.radio().transmitted.len(), expected_tx as usize);
    }

    // Budget spent. The terminal deadline discards the entry in silence.
    let deadline_ms = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_deadline_ms;
    mac.clock()
        .advance_ms(deadline_ms.saturating_sub(mac.clock().now_ms()));
    mac.service_pending_ack_timeouts(&mut on_event).unwrap();

    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
    assert!(mac.tx_queue().is_empty());
    assert_eq!(timeouts, 0, "a best-effort send times out in silence");
}

/// A direct non-ACK unicast — no flood budget, no source route — is exactly
/// one transmission: nothing tracked, nothing retried.
#[test]
fn non_ack_direct_unicast_is_transmitted_exactly_once() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().no_flood(),
        )
        .unwrap();
    assert!(receipt.is_none());
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_acks()
            .next()
            .is_none(),
        "a direct non-ACK send is not tracked"
    );

    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    assert_eq!(mac.radio().transmitted.len(), 1);
    assert!(mac.tx_queue().is_empty());

    mac.clock().advance_ms(1_000_000);
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    assert!(mac.tx_queue().is_empty(), "nothing ever retries");
}

/// A tracked non-ACK send must air a frame that solicits the repeat it waits
/// for. A peer cached at the nibble's maximum flood distance pushes the
/// effective budget past what `FHOPS_REM` can encode; without the clamp the
/// builder silently dropped the field, so the frame flew hop-less while the
/// tracking state armed a retry ladder for a repeat no one could ever send.
#[test]
fn an_unencodable_flood_ceiling_still_airs_hops_on_a_tracked_send() {
    let (mut mac, local_id, peer_key, peer_id) = mac_with_keyed_peer();
    mac.peer_registry_mut().update_route(
        peer_id,
        CachedRoute::Flood {
            hops: MAX_FLOOD_HOPS,
            regions: heapless::Vec::new(),
        },
    );

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_flood_hops(MAX_FLOOD_HOPS + 1),
        )
        .unwrap();
    assert!(receipt.is_none(), "no receipt for a non-ACK send");

    let tracked = mac
        .identity(local_id)
        .unwrap()
        .pending_acks()
        .next()
        .is_some();
    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    let rem = header.flood_hops.map(|hops| hops.remaining());

    assert_eq!(
        rem,
        Some(MAX_FLOOD_HOPS),
        "the budget is clamped, not dropped"
    );
    assert!(tracked, "a flooded non-ACK send is repeat-confirmed");
}

/// The route half of the arming rule: a source-routed send with no flood
/// budget at all still names a repeater that will carry it, so it is tracked.
#[test]
fn non_ack_routed_unicast_without_flood_is_tracked() {
    let (mut mac, local_id, peer_key) = make_sender_mac();
    let route = [RouterHint([0x21, 0x43])];

    let receipt = mac
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            // `no_flood` last: `try_with_source_route` back-fills a flood
            // budget when none is set.
            &SendOptions::default()
                .try_with_source_route(&route)
                .unwrap()
                .no_flood(),
        )
        .unwrap();
    assert!(receipt.is_none(), "no receipt for a non-ACK send");

    let queued = mac.tx_queue_mut().pop_next().expect("queued unicast");
    let header = PacketHeader::parse(queued.frame.as_slice()).unwrap();
    assert!(header.flood_hops.is_none(), "no flood budget was attached");

    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_acks()
            .next()
            .is_some(),
        "the routed hop is expected to repeat, so the send is tracked"
    );
}

/// The overheard repeat that confirms a repeat-only send is a *real* repeater
/// rewrite — FHOPS decremented, a router hint prepended to the trace route, a
/// region code inserted, the frame visibly longer — not the pristine frame the
/// sender transmitted. The confirmation key rides on the MIC, which a repeater
/// may not touch, so the rewrite must still match.
#[test]
fn a_real_repeater_rewrite_confirms_the_senders_repeat_only_entry() {
    let (mut sender, local_id, peer_key) = make_sender_mac();
    let _ = sender
        .queue_unicast(
            local_id,
            &peer_key,
            b"hello",
            &SendOptions::default().with_trace_route(),
        )
        .unwrap();
    let receipt = sole_tracked_receipt(&sender, local_id);
    let _ = block_on(sender.transmit_next(&mut |_, _| {})).unwrap();
    let original = sender.radio().transmitted[0].clone();

    let mut repeater = make_mac();
    repeater.repeater_config_mut().enabled = true;
    repeater.repeater_config_mut().default_region = Some([0x78, 0x53]);
    let _ = repeater
        .add_identity(DummyIdentity::new([0x30; 32]))
        .unwrap();
    repeater
        .radio_mut()
        .queue_received_frame(original.as_slice());
    let handled = block_on(repeater.receive_one(|_, _| {})).unwrap();
    assert!(handled, "the repeater accepts the flood forward");
    let rewritten = repeater
        .tx_queue_mut()
        .pop_next()
        .expect("a queued forward");
    assert!(
        rewritten.frame.len() > original.len(),
        "the rewrite grew the frame (trace hint + region code)"
    );

    sender
        .radio_mut()
        .queue_received_frame(rewritten.frame.as_slice());
    let mut confirmed = None;
    let handled = block_on(sender.receive_one(|identity, event| {
        if let MacEventRef::Forwarded { receipt, .. } = event {
            confirmed = Some((identity, receipt));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(confirmed, Some((local_id, receipt)));
    assert!(
        sender
            .identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none(),
        "the overheard rewrite completed the send"
    );
}

/// The post-transmit listen window that parks all other traffic belongs to
/// ACK-requested sends only; a best-effort flood send must not stall the
/// node's queue for a confirmation it is merely hoping for.
#[test]
fn repeat_confirmed_send_does_not_block_other_traffic() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

    let _ = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default())
        .unwrap();
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    assert_eq!(mac.radio().transmitted.len(), 1);

    let _ = mac
        .queue_broadcast(local_id, b"beacon", &SendOptions::default().no_flood())
        .unwrap();
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    assert_eq!(
        mac.radio().transmitted.len(),
        2,
        "no listen window holds the beacon back"
    );
}

/// Overhearing a repeat completes a repeat-only send outright: `Forwarded`
/// fires and the entry is gone — that repeat was the whole outcome.
#[test]
fn overheard_repeat_completes_a_non_ack_send() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

    let _ = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default())
        .unwrap();
    let receipt = sole_tracked_receipt(&mac, local_id);
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();

    let frame = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    let forwarded = rewrite_forwarded_fixture(frame.as_slice());
    mac.radio_mut().queue_received_frame(forwarded.as_slice());

    let mut confirmed = None;
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::Forwarded { receipt, .. } = event {
            confirmed = Some((identity, receipt));
        }
    }))
    .unwrap();

    assert!(handled);
    assert_eq!(confirmed, Some((local_id, receipt)));
    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
}

/// A repeat that arrives while the retransmission sits in backoff still
/// counts: the queued retry is withdrawn and the send completes.
#[test]
fn late_repeat_withdraws_a_queued_retry() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

    let _ = mac
        .queue_unicast(local_id, &peer_key, b"hello", &SendOptions::default())
        .unwrap();
    let receipt = sole_tracked_receipt(&mac, local_id);
    let _ = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();

    let confirm_deadline_ms = match mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .state
    {
        AckState::AwaitingForward {
            confirm_deadline_ms,
        } => confirm_deadline_ms,
        other => panic!("expected AwaitingForward, got {other:?}"),
    };
    mac.clock()
        .advance_ms(confirm_deadline_ms.saturating_sub(mac.clock().now_ms()));
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    assert_eq!(
        mac.tx_queue().len(),
        1,
        "the retry is waiting out its jitter"
    );

    let frame = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    let forwarded = rewrite_forwarded_fixture(frame.as_slice());
    mac.radio_mut().queue_received_frame(forwarded.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    assert!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .is_none()
    );
    assert!(mac.tx_queue().is_empty(), "the queued retry is withdrawn");
}

/// The same late-repeat handling serves ACK-requested sends: the queued
/// retry is withdrawn and the send moves on to waiting for its ack.
#[test]
fn late_repeat_moves_an_ack_requested_send_to_awaiting_ack() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

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

    let confirm_deadline_ms = match mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .state
    {
        AckState::AwaitingForward {
            confirm_deadline_ms,
        } => confirm_deadline_ms,
        other => panic!("expected AwaitingForward, got {other:?}"),
    };
    mac.clock()
        .advance_ms(confirm_deadline_ms.saturating_sub(mac.clock().now_ms()));
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    assert_eq!(mac.tx_queue().len(), 1);

    let frame = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .resend
        .frame
        .clone();
    let forwarded = rewrite_forwarded_fixture(frame.as_slice());
    mac.radio_mut().queue_received_frame(forwarded.as_slice());
    assert!(block_on(mac.receive_one(|_, _| {})).unwrap());

    assert!(matches!(
        mac.identity(local_id)
            .unwrap()
            .pending_ack(&receipt)
            .unwrap()
            .state,
        AckState::AwaitingAck
    ));
    assert!(mac.tx_queue().is_empty(), "the queued retry is withdrawn");
}

/// An ack that lands while a retransmission is queued must take the
/// retransmission with it; the send is over.
#[test]
fn complete_ack_withdraws_a_queued_retry() {
    let (mut mac, local_id, peer_key) = make_sender_mac();

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

    let confirm_deadline_ms = match mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .state
    {
        AckState::AwaitingForward {
            confirm_deadline_ms,
        } => confirm_deadline_ms,
        other => panic!("expected AwaitingForward, got {other:?}"),
    };
    mac.clock()
        .advance_ms(confirm_deadline_ms.saturating_sub(mac.clock().now_ms()));
    mac.service_pending_ack_timeouts(|_, _| {}).unwrap();
    assert_eq!(mac.tx_queue().len(), 1);

    let ack_trailer = mac
        .identity(local_id)
        .unwrap()
        .pending_ack(&receipt)
        .unwrap()
        .ack_trailer;
    assert_eq!(
        mac.complete_ack(&peer_key, &ack_trailer),
        Some((local_id, receipt))
    );
    assert!(mac.tx_queue().is_empty(), "the queued retry is withdrawn");
}

/// The last line of defense: a queued retransmission whose send no longer
/// has pending state — completed or cancelled through any path — is dropped
/// at the radio's doorstep instead of transmitted.
#[test]
fn transmit_next_drops_a_retry_whose_send_is_finished() {
    let (mut mac, local_id, _peer_key) = make_sender_mac();

    mac.tx_queue_mut()
        .enqueue_with_state(
            TxPriority::Retry,
            b"stale retry",
            Some(SendReceipt(99)),
            Some(local_id),
            0,
            0,
            0,
        )
        .unwrap();

    let result = block_on(mac.transmit_next(&mut |_, _| {})).unwrap();
    assert!(result.is_none());
    assert!(mac.tx_queue().is_empty());
    assert!(mac.radio().transmitted.is_empty(), "nothing went on air");
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

type TestMac = Mac<DummyPlatform, 4, 16, 8, 16, 16, 256, 64>;

fn make_mac() -> TestMac {
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
        stored[1] = flood_hops.decremented().0;
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
        packet.header().unwrap();
        packet.as_bytes_mut()[1] = FloodHops::new(remaining, accumulated).unwrap().0;
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
            .add_identity(crate::test_support::DummyIdentity::new(
                [0x10u8.wrapping_add(index as u8); 32],
            ))
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
        k_enc: [0x21; 32],
        k_mic: [0x42; 32],
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

fn install_channel_on_all(scenario: &mut ModeledScenario, channel_key: ChannelKey) -> ChannelId {
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

    let has_flood_hops = flood_hops.is_some();
    frame[0] = umsh_core::Fcf::new(PacketType::Reserved5, false, has_flood_hops).0;
    let mut cursor = 1usize;
    if let Some((remaining, accumulated)) = flood_hops {
        frame[cursor] = FloodHops::new(remaining, accumulated).unwrap().0;
        cursor += 1;
    }
    if options_len > 0 {
        frame[cursor..cursor + options_len].copy_from_slice(&options_buf[..options_len]);
        cursor += options_len;
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
    /// Construct a dummy identity whose public key is a valid Ed25519
    /// point on the curve.
    ///
    /// `seed` is used as the Ed25519 secret-key bytes when the
    /// `software-crypto` feature is active (which it is during workspace
    /// tests via feature unification). This means callers can keep passing
    /// arbitrary 32-byte arrays as test fingerprints and the resulting
    /// public keys will pass `is_valid_ed25519_public_key`. Without the
    /// feature, the raw bytes are used directly (preserving the previous
    /// behavior for builds that don't include the curve validator).
    fn new(seed: [u8; 32]) -> Self {
        #[cfg(feature = "software-crypto")]
        let public_key = {
            use umsh_crypto::software::SoftwareIdentity;
            *SoftwareIdentity::from_secret_bytes(&seed).public_key()
        };
        #[cfg(not(feature = "software-crypto"))]
        let public_key = PublicKey(seed);
        Self { public_key }
    }
}

/// Two distinct peer public keys whose 3-byte node hints collide in **both**
/// cfg paths, for exercising ambiguous-hint candidate iteration.
///
/// The seeds share the prefix `AB AB AB`, so without `software-crypto`
/// (where `DummyIdentity` uses the seed bytes verbatim as the public key)
/// the hints collide trivially. With `software-crypto` the seeds derive real
/// Ed25519 points — the pair below was found by a one-off birthday search
/// over seeds of the form `AB AB AB || u64-LE counter || zeros`
/// (counters 1222 and 3291), whose derived public keys share the prefix
/// `FB 24 12`. The assertions re-verify the collision at runtime so a change
/// in key derivation cannot silently turn these tests into non-tests.
fn colliding_hint_peer_keys() -> (PublicKey, PublicKey) {
    let mut seed_a = [0u8; 32];
    seed_a[..3].copy_from_slice(&[0xAB, 0xAB, 0xAB]);
    seed_a[3..11].copy_from_slice(&1222u64.to_le_bytes());
    let mut seed_b = [0u8; 32];
    seed_b[..3].copy_from_slice(&[0xAB, 0xAB, 0xAB]);
    seed_b[3..11].copy_from_slice(&3291u64.to_le_bytes());

    let key_a = *DummyIdentity::new(seed_a).public_key();
    let key_b = *DummyIdentity::new(seed_b).public_key();
    assert_ne!(key_a, key_b, "candidate keys must be distinct");
    assert_eq!(key_a.hint(), key_b.hint(), "candidate hints must collide");
    (key_a, key_b)
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
    fn new_cipher(&self, _key: &[u8; 32]) -> Self::Cipher {
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
    /// Signal quality reported for every received frame. Defaults to the
    /// zeroes `RxInfo::default` would give, so tests that do not care read
    /// exactly as they did before this was settable.
    rx_rssi: i16,
    rx_snr: Snr,
    /// Where every received frame is reported as having come from.
    rx_origin: RxOrigin,
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

    fn queue_received_mac_ack(&mut self, ack_trailer: [u8; 8]) {
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .mac_ack(ack_trailer)
            .build()
            .unwrap();
        let mut stored = heapless::Vec::new();
        for byte in frame {
            stored.push(*byte).unwrap();
        }
        self.received.push_back(stored).unwrap();
    }

    /// An echo request that arrives asking for both trace options, the way a
    /// ping does.
    fn queue_received_traced_echo_request(
        &mut self,
        source: &DummyIdentity,
        keys: &PairwiseKeys,
        dst: &umsh_core::NodeHint,
        payload: &[u8],
    ) {
        let mut buf = [0u8; 256];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(*dst)
            .source_full(source.public_key())
            .frame_counter(7)
            .encrypted()
            .trace_route()
            .trace_signal()
            .payload(payload)
            .build()
            .unwrap();
        CryptoEngine::new(DummyAes, DummySha)
            .seal_packet(&mut packet, keys)
            .unwrap();
        self.queue_received_frame(packet.as_bytes());
    }

    /// A MAC ack as it arrives after crossing `trace` repeaters, each having
    /// prepended its hint on the way.
    fn queue_received_mac_ack_with_trace(&mut self, ack_trailer: [u8; 8], trace: &[RouterHint]) {
        let mut encoded = [0u8; 30];
        let mut used = 0usize;
        for hop in trace {
            encoded[used..used + 2].copy_from_slice(&hop.0);
            used += 2;
        }
        let mut buf = [0u8; 256];
        let frame = PacketBuilder::new(&mut buf)
            .mac_ack(ack_trailer)
            .option(OptionNumber::TraceRoute, &encoded[..used])
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
        self.queue_received_unicast_with_thresholds(
            source,
            keys,
            dst,
            payload,
            ack_requested,
            frame_counter,
            flood_hops,
            trace_route,
            source_route,
            None,
            None,
        );
    }

    fn queue_received_unicast_with_thresholds(
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
        min_rssi: Option<i16>,
        min_snr: Option<i8>,
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
        // `min_rssi`/`min_snr` are the dBm/dB thresholds. Min RSSI is encoded
        // on the wire as an unsigned negated-dBm byte, so a positive dBm
        // threshold is not representable and clamps to 0. Min SNR is a signed
        // 1-byte dB value.
        let builder = if let Some(min_rssi) = min_rssi {
            builder.option(OptionNumber::MinRssi, &[(-min_rssi).clamp(0, 255) as u8])
        } else {
            builder
        };
        let builder = if let Some(min_snr) = min_snr {
            builder.option(OptionNumber::MinSnr, &[min_snr as u8])
        } else {
            builder
        };
        let mut packet = builder.payload(payload).build().unwrap();
        if let Some((remaining, accumulated)) = flood_hops {
            packet.header().unwrap();
            packet.as_bytes_mut()[1] = FloodHops::new(remaining, accumulated).unwrap().0;
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
            packet.header().unwrap();
            packet.as_bytes_mut()[1] = FloodHops::new(remaining, accumulated).unwrap().0;
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
        if !matches!(options.cad, umsh_hal::CadPolicy::Skip) {
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
            rssi: self.rx_rssi,
            snr: self.rx_snr,
            lqi: None,
            origin: self.rx_origin,
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
