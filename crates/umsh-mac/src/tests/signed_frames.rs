//! Frames signed by their sender: a Frame Signature option on a broadcast,
//! `D` on a frame with SECINFO.

use super::*;

use umsh_core::{SIGNATURE_INPUT_MAX, Scf};
use umsh_crypto::software::verify_frame_signature;

const CHANNEL: ChannelKey = ChannelKey([0x5A; 32]);
const SEED: [u8; 32] = [0x10; 32];

fn sender() -> (CryptoMac, LocalIdentityId, PublicKey) {
    let mut mac = make_crypto_mac();
    let identity = DummyIdentity::new(SEED);
    let key = *identity.public_key();
    let id = mac.add_identity(identity).unwrap();
    mac.add_channel(CHANNEL).unwrap();
    (mac, id, key)
}

fn sent_frame(mac: &mut CryptoMac) -> std::vec::Vec<u8> {
    mac.tx_queue_mut().pop_next().unwrap().frame.to_vec()
}

fn verifies(
    header: &PacketHeader,
    frame: &[u8],
    key: &PublicKey,
    channel: Option<&umsh_core::ChannelCommitment>,
) -> bool {
    let mut scratch = [0u8; SIGNATURE_INPUT_MAX];
    verify_frame_signature(header, frame, key, None, channel, &mut scratch)
}

#[test]
fn a_signed_multicast_is_sealed_with_a_verifiable_signature() {
    for options in [
        SendOptions::default().with_signature(),
        SendOptions::default().with_signature().unencrypted(),
    ] {
        let (mut mac, id, key) = sender();
        block_on(mac.send_multicast(id, &CHANNEL, b"mayday", &options)).unwrap();
        let mut frame = sent_frame(&mut mac);
        let header = PacketHeader::parse(&frame).unwrap();
        let sec_info = header.sec_info.unwrap();
        assert!(sec_info.scf.signed());
        assert_eq!(header.signature().unwrap().counter, sec_info.frame_counter);

        let derived = mac.crypto().derive_channel_keys(&CHANNEL);
        let keys = PairwiseKeys {
            k_enc: derived.k_enc,
            k_mic: derived.k_mic,
        };
        let payload = mac
            .crypto()
            .open_packet(&mut frame, &header, &keys, None)
            .unwrap();
        assert_eq!(&frame[payload], b"mayday");
        assert!(verifies(&header, &frame, &key, Some(&derived.commitment)));
        // Another channel's commitment does not verify it.
        let other = mac
            .crypto()
            .derive_channel_commitment(&ChannelKey([0x11; 32]));
        assert!(!verifies(&header, &frame, &key, Some(&other)));
    }
}

/// A signed broadcast draws its counter from the identity's one sequence,
/// and an unsigned one draws none.
#[test]
fn a_signed_broadcast_carries_the_identitys_next_counter() {
    let (mut mac, id, key) = sender();
    let signed = SendOptions::default().with_signature();

    block_on(mac.send_broadcast(id, b"one", &signed)).unwrap();
    let first = sent_frame(&mut mac);
    let header = PacketHeader::parse(&first).unwrap();
    let counter = header.signature().unwrap().counter;
    assert!(verifies(&header, &first, &key, None));

    block_on(mac.send_broadcast(id, b"plain", &SendOptions::default())).unwrap();
    let plain = sent_frame(&mut mac);
    assert_eq!(PacketHeader::parse(&plain).unwrap().signature(), None);

    block_on(mac.send_multicast(id, &CHANNEL, b"two", &signed)).unwrap();
    let multicast = sent_frame(&mut mac);
    let multicast_counter = PacketHeader::parse(&multicast)
        .unwrap()
        .sec_info
        .unwrap()
        .frame_counter;
    assert_eq!(multicast_counter, counter.wrapping_add(1));

    block_on(mac.send_broadcast(id, b"three", &signed)).unwrap();
    let third = sent_frame(&mut mac);
    let header = PacketHeader::parse(&third).unwrap();
    assert_eq!(header.signature().unwrap().counter, counter.wrapping_add(2));
    assert!(verifies(&header, &third, &key, None));
}

/// Signing awaits the identity, so the synchronous calls refuse it, and so
/// do the sends that have no signing path.
#[test]
fn only_the_async_broadcast_and_multicast_sends_sign() {
    let (mut mac, id, _) = sender();
    let peer = DummyIdentity::new([0x22; 32]);
    let peer = *peer.public_key();
    let peer_id = mac.add_peer(peer).unwrap();
    mac.install_pairwise_keys(
        id,
        peer_id,
        PairwiseKeys {
            k_enc: [1; 32],
            k_mic: [2; 32],
        },
    )
    .unwrap();
    let signed = SendOptions::default().with_signature();
    assert_eq!(
        mac.queue_broadcast(id, b"x", &signed),
        Err(SendError::SigningUnsupported)
    );
    assert_eq!(
        mac.queue_multicast(id, &CHANNEL, b"x", &signed),
        Err(SendError::SigningUnsupported)
    );
    assert_eq!(
        mac.queue_unicast(id, &peer, b"x", &signed),
        Err(SendError::SigningUnsupported)
    );
    assert_eq!(
        mac.queue_blind_unicast(id, &peer, &CHANNEL, b"x", &signed),
        Err(SendError::SigningUnsupported)
    );
    assert!(mac.tx_queue_mut().pop_next().is_none());
}

/// A signed send at exactly `payload_capacity` fills the frame, and one byte
/// more is refused. The full-source signed broadcast has 151 bytes.
#[test]
fn a_signed_send_at_capacity_fills_the_frame() {
    let max_frame = 255;
    let broadcast = SendOptions::default()
        .with_signature()
        .with_full_source()
        .no_flood();
    let multicast = SendOptions::default().with_signature().with_full_source();
    for (destination, options) in [
        (SendDestination::Broadcast, &broadcast),
        (SendDestination::Multicast(&CHANNEL), &multicast),
    ] {
        let (mut mac, id, key) = sender();
        let capacity = mac.payload_capacity(id, destination, options).unwrap();
        if destination == SendDestination::Broadcast {
            assert_eq!(capacity, 151);
        }
        let payload = std::vec![0x42u8; capacity + 1];
        let send = |mac: &mut CryptoMac, payload: &[u8]| match destination {
            SendDestination::Broadcast => block_on(mac.send_broadcast(id, payload, options)),
            _ => block_on(mac.send_multicast(id, &CHANNEL, payload, options)),
        };
        send(&mut mac, &payload[..capacity]).unwrap();
        let frame = sent_frame(&mut mac);
        assert_eq!(frame.len(), max_frame);
        assert!(send(&mut mac, &payload).is_err());

        if destination == SendDestination::Broadcast {
            let header = PacketHeader::parse(&frame).unwrap();
            assert!(verifies(&header, &frame, &key, None));
        } else {
            let header = PacketHeader::parse(&frame).unwrap();
            assert!(header.sec_info.unwrap().scf.0 & Scf::SIGNED != 0);
        }
    }
}

// ── Receiving ────────────────────────────────────────────────────────────

const OTHER_SEED: [u8; 32] = [0x30; 32];

fn engine() -> umsh_crypto::software::SoftwareCryptoEngine {
    use umsh_crypto::software::{SoftwareAes, SoftwareSha256};
    CryptoEngine::new(SoftwareAes, SoftwareSha256)
}

fn key_of(seed: [u8; 32]) -> PublicKey {
    *DummyIdentity::new(seed).public_key()
}

fn sign_with(seed: [u8; 32], input: &[u8]) -> [u8; 64] {
    block_on(umsh_crypto::software::SoftwareIdentity::from_secret_bytes(&seed).sign(input)).unwrap()
}

/// A signed multicast from `seed`'s key on `channel`, with `counter`. With
/// `hint_only` its source is a hint; with `forge` it is signed by
/// `OTHER_SEED` instead, so its signature fails against the key it names.
fn multicast_from(
    seed: [u8; 32],
    channel: &ChannelKey,
    counter: u32,
    hint_only: bool,
    forge: bool,
) -> std::vec::Vec<u8> {
    let engine = engine();
    let derived = engine.derive_channel_keys(channel);
    let key = key_of(seed);
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf).multicast(derived.channel_id);
    let builder = if hint_only {
        builder.source_hint(key.hint())
    } else {
        builder.source_full(&key)
    };
    let mut packet = builder
        .frame_counter(counter)
        .encrypted()
        .signed()
        .payload(b"mayday")
        .build()
        .unwrap();
    let header = packet.header().unwrap();
    let mut input = [0u8; SIGNATURE_INPUT_MAX];
    let len = umsh_core::signature_input(
        &header,
        packet.as_bytes(),
        None,
        Some(&derived.commitment),
        &mut input,
    )
    .unwrap();
    let signer = if forge { OTHER_SEED } else { seed };
    let signature = sign_with(signer, &input[..len]);
    packet
        .signature_slot_mut()
        .unwrap()
        .copy_from_slice(&signature);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    engine.seal_packet(&mut packet, &keys).unwrap();
    packet.as_bytes().to_vec()
}

/// A signed broadcast from `seed`'s key with `counter`.
fn broadcast_from(seed: [u8; 32], counter: u32, hint_only: bool) -> std::vec::Vec<u8> {
    signed_broadcast(seed, counter, hint_only, None)
}

/// [`broadcast_from`], allowed `flood_hops` if given.
fn signed_broadcast(
    seed: [u8; 32],
    counter: u32,
    hint_only: bool,
    flood_hops: Option<u8>,
) -> std::vec::Vec<u8> {
    let key = key_of(seed);
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf).broadcast();
    let builder = if hint_only {
        builder.source_hint(key.hint())
    } else {
        builder.source_full(&key)
    };
    let builder = match flood_hops {
        Some(hops) => builder.flood_hops(hops),
        None => builder,
    };
    let mut frame = builder
        .signed(counter)
        .payload(b"advert")
        .build()
        .unwrap()
        .to_vec();
    let header = PacketHeader::parse(&frame).unwrap();
    let mut input = [0u8; SIGNATURE_INPUT_MAX];
    let len = umsh_core::signature_input(&header, &frame, None, None, &mut input).unwrap();
    let range = header.signature().unwrap().range.clone();
    frame[range].copy_from_slice(&sign_with(seed, &input[..len]));
    frame
}

#[derive(Debug, PartialEq, Eq)]
struct Delivery {
    signature: SignatureStatus,
    acceptance: Option<RxAcceptance>,
    from_key: Option<PublicKey>,
    sender_authenticated: bool,
}

fn receiver() -> CryptoMac {
    let mut mac = make_crypto_mac();
    mac.add_identity(DummyIdentity::new([0x20; 32])).unwrap();
    mac.add_channel(CHANNEL).unwrap();
    mac
}

/// What `mac` delivers of `frame`, once per frame.
fn receive(mac: &mut CryptoMac, frame: &[u8]) -> Option<Delivery> {
    mac.radio_mut().queue_received_frame(frame);
    let mut delivered = None;
    block_on(mac.receive_one(|_, event| {
        if let MacEventRef::Received(packet) = event {
            delivered.get_or_insert(Delivery {
                signature: packet.signature(),
                acceptance: packet.acceptance(),
                from_key: packet.from_key(),
                sender_authenticated: packet.sender_authenticated(),
            });
        }
    }))
    .unwrap();
    delivered
}

fn verified(acceptance: RxAcceptance, from: PublicKey) -> Option<Delivery> {
    Some(Delivery {
        signature: SignatureStatus::Verified,
        acceptance: Some(acceptance),
        from_key: Some(from),
        sender_authenticated: true,
    })
}

/// A stranger's signed multicast is judged by a window kept for its key:
/// first contact, then an exact replay dropped, then the next frame.
#[test]
fn a_strangers_signed_multicast_is_judged_by_its_own_window() {
    let mut mac = receiver();
    let from = key_of(SEED);
    let first = multicast_from(SEED, &CHANNEL, 100, false, false);
    assert_eq!(
        receive(&mut mac, &first),
        verified(RxAcceptance::FirstContact, from)
    );
    assert_eq!(receive(&mut mac, &first), None);
    let next = multicast_from(SEED, &CHANNEL, 101, false, false);
    assert_eq!(
        receive(&mut mac, &next),
        verified(RxAcceptance::Advanced, from)
    );
    assert!(
        mac.rx_windows()
            .strangers()
            .any(|entry| *entry.key() == from)
    );
}

/// A known peer's signed multicast and signed broadcast are judged by its
/// persisted window, hint-only included.
#[test]
fn a_known_peers_signed_frames_share_one_window() {
    let mut mac = receiver();
    let from = key_of(SEED);
    mac.add_peer(from).unwrap();
    let multicast = multicast_from(SEED, &CHANNEL, 10, true, false);
    assert_eq!(
        receive(&mut mac, &multicast),
        verified(RxAcceptance::FirstContact, from)
    );
    let broadcast = broadcast_from(SEED, 11, true);
    assert_eq!(
        receive(&mut mac, &broadcast),
        verified(RxAcceptance::Advanced, from)
    );
    assert_eq!(receive(&mut mac, &broadcast), None);
    assert_eq!(receive(&mut mac, &multicast), None);
    // A frame the window already passed is spent, whatever its family.
    let late = broadcast_from(SEED, 10, true);
    assert_eq!(receive(&mut mac, &late), None);
    assert!(mac.rx_windows().is_registered(&from));
}

/// A peer's advertisements delivered out of order: the late one is
/// delivered as a backfill, which the application keeps only to fill gaps,
/// and a replay of either is dropped.
#[test]
fn a_reordered_signed_advertisement_is_a_backfill() {
    let mut mac = receiver();
    let from = key_of(SEED);
    mac.add_peer(from).unwrap();
    let baseline = broadcast_from(SEED, 100, false);
    assert_eq!(
        receive(&mut mac, &baseline),
        verified(RxAcceptance::FirstContact, from)
    );
    let newer = broadcast_from(SEED, 102, false);
    assert_eq!(
        receive(&mut mac, &newer),
        verified(RxAcceptance::Advanced, from)
    );
    let late = broadcast_from(SEED, 101, false);
    assert_eq!(
        receive(&mut mac, &late),
        verified(RxAcceptance::Backfilled, from)
    );
    for stale in [&baseline, &late, &newer] {
        assert_eq!(receive(&mut mac, stale), None);
    }
}

/// A hint-only signed broadcast from a key the receiver does not hold is
/// delivered, unverified, as an unsigned broadcast would be.
#[test]
fn a_hint_only_signed_broadcast_from_a_stranger_is_not_verified() {
    let mut mac = receiver();
    let frame = broadcast_from(SEED, 5, true);
    assert_eq!(
        receive(&mut mac, &frame),
        Some(Delivery {
            signature: SignatureStatus::NotVerified,
            acceptance: None,
            from_key: None,
            sender_authenticated: false,
        })
    );
    // With no window to judge it, a copy is delivered again.
    assert!(receive(&mut mac, &frame).is_some());
    let full = broadcast_from(SEED, 6, false);
    assert_eq!(
        receive(&mut mac, &full),
        verified(RxAcceptance::FirstContact, key_of(SEED))
    );
}

/// A badly signed multicast naming a known peer takes the unsigned path:
/// delivered unverified, a copy dropped by the per-channel window, and the
/// peer's signed-frame window untouched.
#[test]
fn a_badly_signed_multicast_takes_the_unsigned_path() {
    let mut mac = receiver();
    let from = key_of(SEED);
    mac.add_peer(from).unwrap();
    let forged = multicast_from(SEED, &CHANNEL, 500, true, true);
    let delivery = receive(&mut mac, &forged).unwrap();
    assert_eq!(delivery.signature, SignatureStatus::NotVerified);
    assert!(!delivery.sender_authenticated);
    assert_eq!(receive(&mut mac, &forged), None);
    assert!(
        !mac.rx_windows()
            .get(&from)
            .unwrap()
            .replay_window
            .is_established()
    );

    // An unresolved hint goes through the unknown-source duplicate cache.
    let stranger = multicast_from(OTHER_SEED, &CHANNEL, 7, true, true);
    assert_eq!(
        receive(&mut mac, &stranger).unwrap().signature,
        SignatureStatus::NotVerified
    );
    assert_eq!(receive(&mut mac, &stranger), None);
    assert!(mac.rx_windows().get(&key_of(OTHER_SEED)).is_none());
}

/// Counter occupancy never drops a frame before its signature is checked:
/// a forgery reusing a counter the named peer already spent is judged on
/// the unsigned path, not refused by the peer's window.
#[test]
fn a_forgery_reusing_a_spent_counter_is_not_dropped_unverified() {
    let mut mac = receiver();
    let from = key_of(SEED);
    mac.add_peer(from).unwrap();
    let genuine = multicast_from(SEED, &CHANNEL, 500, true, false);
    assert_eq!(
        receive(&mut mac, &genuine),
        verified(RxAcceptance::FirstContact, from)
    );
    let forged = multicast_from(SEED, &CHANNEL, 500, true, true);
    assert_eq!(
        receive(&mut mac, &forged).unwrap().signature,
        SignatureStatus::NotVerified
    );
}

/// A stranger that becomes a peer keeps its window, so a frame accepted
/// before registration is still a replay after it.
#[test]
fn a_promoted_stranger_keeps_its_window() {
    let mut mac = receiver();
    let from = key_of(SEED);
    let frame = multicast_from(SEED, &CHANNEL, 100, false, false);
    assert!(receive(&mut mac, &frame).is_some());
    mac.add_peer(from).unwrap();
    assert_eq!(receive(&mut mac, &frame), None);
    let next = multicast_from(SEED, &CHANNEL, 101, false, false);
    assert_eq!(
        receive(&mut mac, &next),
        verified(RxAcceptance::Advanced, from)
    );
}

/// A verified signer's counter is spent across channels that share an
/// identifier, and a frame re-sealed onto the other channel fails its
/// signature there.
#[test]
fn a_signers_counter_spans_colliding_channels() {
    let mut second = [0x77; 32];
    second[..4].copy_from_slice(&0x0001_D29Au32.to_be_bytes());
    let second = ChannelKey(second);
    let mut mac = receiver();
    mac.add_channel(second).unwrap();
    let from = key_of(SEED);

    let first = multicast_from(SEED, &CHANNEL, 40, false, false);
    assert_eq!(
        receive(&mut mac, &first),
        verified(RxAcceptance::FirstContact, from)
    );
    let again = multicast_from(SEED, &second, 40, false, false);
    assert_eq!(receive(&mut mac, &again), None);

    // Re-sealed under the second key with the first channel's signature.
    let engine = engine();
    let mut opened = first.clone();
    let header = PacketHeader::parse(&opened).unwrap();
    let derived = engine.derive_channel_keys(&CHANNEL);
    let keys = PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    };
    engine
        .open_packet(&mut opened, &header, &keys, None)
        .unwrap();
    let signature: [u8; 64] = opened[header.signature().unwrap().range.clone()]
        .try_into()
        .unwrap();
    let derived_b = engine.derive_channel_keys(&second);
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .multicast(derived_b.channel_id)
        .source_full(&from)
        .frame_counter(41)
        .encrypted()
        .signed()
        .payload(b"mayday")
        .build()
        .unwrap();
    packet
        .signature_slot_mut()
        .unwrap()
        .copy_from_slice(&signature);
    engine
        .seal_packet(
            &mut packet,
            &PairwiseKeys {
                k_enc: derived_b.k_enc,
                k_mic: derived_b.k_mic,
            },
        )
        .unwrap();
    let transplanted = packet.as_bytes().to_vec();
    assert_eq!(
        receive(&mut mac, &transplanted).unwrap().signature,
        SignatureStatus::NotVerified
    );
}

/// A known peer's verified frame far behind its baseline is dropped and
/// asks the peer to resynchronize, once per retry interval. A stranger's is
/// only dropped.
#[test]
fn a_far_stale_signed_frame_from_a_peer_starts_a_resync() {
    let mut mac = receiver();
    let from = key_of(SEED);
    mac.add_peer(from).unwrap();
    assert!(receive(&mut mac, &multicast_from(SEED, &CHANNEL, 5000, true, false)).is_some());
    assert!(mac.tx_queue_mut().pop_next().is_none());

    assert_eq!(
        receive(&mut mac, &multicast_from(SEED, &CHANNEL, 10, true, false)),
        None
    );
    let probe = mac.tx_queue_mut().pop_next().expect("an Echo Request");
    let header = PacketHeader::parse(&probe.frame).unwrap();
    assert!(matches!(
        header.packet_type(),
        PacketType::Unicast | PacketType::UnicastAckReq
    ));
    assert_eq!(receive(&mut mac, &broadcast_from(SEED, 11, true)), None);
    assert!(mac.tx_queue_mut().pop_next().is_none());

    let mut mac = receiver();
    assert!(
        receive(
            &mut mac,
            &multicast_from(OTHER_SEED, &CHANNEL, 5000, false, false)
        )
        .is_some()
    );
    assert_eq!(
        receive(
            &mut mac,
            &multicast_from(OTHER_SEED, &CHANNEL, 10, false, false)
        ),
        None
    );
    assert!(mac.tx_queue_mut().pop_next().is_none());
}

/// Two MACs: a signed multicast and a signed broadcast sent through the
/// send API verify at the receiver.
#[test]
fn signed_sends_verify_at_the_receiver() {
    let (mut sender, id, from) = sender();
    let mut mac = receiver();
    block_on(sender.send_multicast(
        id,
        &CHANNEL,
        b"mayday",
        &SendOptions::default().with_signature().with_full_source(),
    ))
    .unwrap();
    let frame = sent_frame(&mut sender);
    assert_eq!(
        receive(&mut mac, &frame),
        verified(RxAcceptance::FirstContact, from)
    );
    block_on(sender.send_broadcast(
        id,
        b"advert",
        &SendOptions::default().with_signature().with_full_source(),
    ))
    .unwrap();
    let frame = sent_frame(&mut sender);
    assert_eq!(
        receive(&mut mac, &frame),
        verified(RxAcceptance::Advanced, from)
    );
}

/// A signed unicast is verified against the key that opened it, and its
/// counter is judged by the pairwise path as any unicast's is.
#[test]
fn a_signed_unicast_is_verified_against_its_pairwise_sender() {
    let mut mac = receiver();
    let local = *mac
        .identity(LocalIdentityId(0))
        .unwrap()
        .identity()
        .public_key();
    let from = key_of(SEED);
    let peer_id = mac.add_peer(from).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(LocalIdentityId(0), peer_id, keys.clone())
        .unwrap();

    let build = |forge: bool| {
        let mut buf = [0u8; 256];
        let mut packet = PacketBuilder::new(&mut buf)
            .unicast(local.hint())
            .source_full(&from)
            .frame_counter(9)
            .encrypted()
            .signed()
            .payload(b"hello")
            .build()
            .unwrap();
        let header = packet.header().unwrap();
        let mut input = [0u8; SIGNATURE_INPUT_MAX];
        let len =
            umsh_core::signature_input(&header, packet.as_bytes(), None, None, &mut input).unwrap();
        let signature = sign_with(if forge { OTHER_SEED } else { SEED }, &input[..len]);
        packet
            .signature_slot_mut()
            .unwrap()
            .copy_from_slice(&signature);
        engine().seal_packet(&mut packet, &keys).unwrap();
        packet.as_bytes().to_vec()
    };
    let delivery = receive(&mut mac, &build(false)).unwrap();
    assert_eq!(delivery.signature, SignatureStatus::Verified);
    assert_eq!(delivery.acceptance, Some(RxAcceptance::FirstContact));
    assert!(delivery.sender_authenticated);

    // A bad signature on a unicast still authenticates its sender pairwise.
    let mut mac2 = receiver();
    let peer_id = mac2.add_peer(from).unwrap();
    mac2.install_pairwise_keys(LocalIdentityId(0), peer_id, keys.clone())
        .unwrap();
    let delivery = receive(&mut mac2, &build(true)).unwrap();
    assert_eq!(delivery.signature, SignatureStatus::NotVerified);
    assert!(delivery.sender_authenticated);
}

// ── Verification budget ──────────────────────────────────────────────────

const PER_SECOND: u32 = umsh_crypto::budget::VERIFY_BUDGET_PER_SECOND;

/// Spend the receiver's whole verification budget on `OTHER_SEED`'s
/// broadcasts.
fn spend_verify_budget(mac: &mut CryptoMac) {
    for counter in 1..=PER_SECOND {
        assert!(receive(mac, &broadcast_from(OTHER_SEED, counter, false)).is_some());
    }
    assert_eq!(mac.counters().rx_verify_over_budget, 0);
}

/// Past the verification budget a signed frame is dropped and counted, never
/// delivered as unverified, and spends nothing of its signer's window. The
/// budget refills with time.
#[test]
fn a_signed_frame_past_the_verify_budget_is_dropped_not_unverified() {
    let mut mac = receiver();
    spend_verify_budget(&mut mac);
    let from = key_of(SEED);
    let late = broadcast_from(SEED, 10, false);
    assert_eq!(receive(&mut mac, &late), None);
    let multicast = multicast_from(SEED, &CHANNEL, 11, false, false);
    assert_eq!(receive(&mut mac, &multicast), None);
    assert_eq!(mac.counters().rx_verify_over_budget, 2);

    mac.clock().advance_ms(1_000);
    assert_eq!(
        receive(&mut mac, &late),
        verified(RxAcceptance::FirstContact, from)
    );
    assert_eq!(
        receive(&mut mac, &multicast),
        verified(RxAcceptance::Advanced, from)
    );
}

/// A flood past the verification budget is still repeated: forwarding never
/// waited on the signature.
#[test]
fn a_flood_past_the_verify_budget_is_still_forwarded() {
    let mut mac = receiver();
    mac.repeater_config_mut().enabled = true;
    spend_verify_budget(&mut mac);
    let forwarded = mac.counters().forwarded;
    let flood = signed_broadcast(SEED, 10, false, Some(3));
    assert_eq!(receive(&mut mac, &flood), None);
    assert_eq!(mac.counters().rx_verify_over_budget, 1);
    assert_eq!(mac.counters().forwarded, forwarded + 1);
}

/// A signed unicast past the budget is dropped before it spends its counter
/// or earns an ack, so its sender's retry is taken once the budget refills.
#[test]
fn a_signed_unicast_past_the_verify_budget_waits_for_its_retry() {
    let mut mac = receiver();
    let local = *mac
        .identity(LocalIdentityId(0))
        .unwrap()
        .identity()
        .public_key();
    let from = key_of(SEED);
    let peer_id = mac.add_peer(from).unwrap();
    let keys = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(LocalIdentityId(0), peer_id, keys.clone())
        .unwrap();
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .unicast(local.hint())
        .source_full(&from)
        .frame_counter(9)
        .encrypted()
        .ack_requested()
        .signed()
        .payload(b"hello")
        .build()
        .unwrap();
    let header = packet.header().unwrap();
    let mut input = [0u8; SIGNATURE_INPUT_MAX];
    let len =
        umsh_core::signature_input(&header, packet.as_bytes(), None, None, &mut input).unwrap();
    packet
        .signature_slot_mut()
        .unwrap()
        .copy_from_slice(&sign_with(SEED, &input[..len]));
    engine().seal_packet(&mut packet, &keys).unwrap();
    let frame = packet.as_bytes().to_vec();

    spend_verify_budget(&mut mac);
    while mac.tx_queue_mut().pop_next().is_some() {}
    assert_eq!(receive(&mut mac, &frame), None);
    assert!(mac.tx_queue_mut().pop_next().is_none(), "nothing acks it");
    assert_eq!(mac.counters().rx_verify_over_budget, 1);

    mac.clock().advance_ms(1_000);
    let delivery = receive(&mut mac, &frame).unwrap();
    assert_eq!(delivery.signature, SignatureStatus::Verified);
    assert_eq!(delivery.acceptance, Some(RxAcceptance::FirstContact));
    assert!(
        mac.tx_queue_mut().pop_next().is_some(),
        "its retry is acked"
    );
}

/// A multicast teaches a route to the peer it names only when that peer's
/// signature verifies: the channel key proves membership, not who sent it.
/// Off the peer's own transmitter, with no flood budget, a genuine one
/// makes it a direct neighbor; a forgery naming it makes it nothing.
#[test]
fn only_a_verified_multicast_teaches_a_route() {
    let from = key_of(SEED);
    for forge in [true, false] {
        let mut mac = receiver();
        let peer_id = mac.add_peer(from).unwrap();
        let frame = multicast_from(SEED, &CHANNEL, 40, false, forge);
        assert!(receive(&mut mac, &frame).is_some());
        let expected = (!forge).then_some(CachedRoute::Direct);
        assert_eq!(
            mac.peer_registry().get(peer_id).unwrap().route,
            expected,
            "forge={forge}"
        );
    }
}
