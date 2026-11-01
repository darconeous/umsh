//! Channels whose distinct keys derive the same two-byte identifier.
//!
//! Each key keeps its own table entry, sends name a channel by its key, and
//! a received frame is tried against every key sharing its identifier until
//! one authenticates it.

use super::*;

use umsh_crypto::software::{SoftwareAes, SoftwareSha256};

/// The test platform with real AES and SHA-256: under the stub hash every
/// channel key derives the same keys, so channels could not be told apart.
struct ChannelPlatform;

impl Platform for ChannelPlatform {
    type Identity = DummyIdentity;
    type Aes = SoftwareAes;
    type Sha = SoftwareSha256;
    type Radio = DummyRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = DummyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}

type ChannelMac = Mac<
    ChannelPlatform,
    4,
    16,
    8,
    16,
    16,
    256,
    64,
    { crate::DEFAULT_CHANNEL_REPLAY },
    { crate::DEFAULT_CHANNEL_HINT_REPLAY },
    4,
>;

fn make_channel_mac() -> ChannelMac {
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(SoftwareAes, SoftwareSha256),
        DummyClock {
            now_ms: Cell::new(123),
        },
        DummyRng(7),
        DummyCounterStore::default(),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

/// An encrypted multicast from `source` sealed under `key`, with `counter`.
fn multicast_frame(
    mac: &ChannelMac,
    source: &PublicKey,
    key: &ChannelKey,
    counter: u32,
) -> std::vec::Vec<u8> {
    let derived = mac.crypto().derive_channel_keys(key);
    let mut buf = [0u8; 256];
    let mut packet = PacketBuilder::new(&mut buf)
        .multicast(derived.channel_id)
        .source_full(source)
        .frame_counter(counter)
        .encrypted()
        .payload(b"group")
        .build()
        .unwrap();
    mac.crypto()
        .seal_packet(&mut packet, &channel_pairwise(mac, key))
        .unwrap();
    packet.as_bytes().to_vec()
}

/// A blind unicast from `source` (full key or hint) to `dst`, sealed under
/// `pairwise` and `key`.
fn blind_frame(
    mac: &ChannelMac,
    source: Result<&PublicKey, NodeHint>,
    dst: NodeHint,
    pairwise: &PairwiseKeys,
    key: &ChannelKey,
    counter: u32,
) -> std::vec::Vec<u8> {
    let channel_keys = mac.crypto().derive_channel_keys(key);
    let blind_keys = mac.crypto().derive_blind_keys(pairwise, &channel_keys);
    let mut buf = [0u8; 256];
    let builder = PacketBuilder::new(&mut buf).blind_unicast(channel_keys.channel_id, dst);
    let builder = match source {
        Ok(key) => builder.source_full(key),
        Err(hint) => builder.source_hint(hint),
    };
    let mut packet = builder
        .frame_counter(counter)
        .payload(b"hello")
        .build()
        .unwrap();
    mac.crypto()
        .seal_blind_packet(&mut packet, &blind_keys, &channel_keys)
        .unwrap();
    packet.as_bytes().to_vec()
}

const FIRST: ChannelKey = ChannelKey([0x5A; 32]);

/// A key other than [`FIRST`] that derives the same identifier: the first
/// of `n ‖ 77…77`, counting `n` up from zero, that does. The search takes
/// seconds in a debug build, so its result is written down and checked.
fn colliding_key(mac: &ChannelMac, key: &ChannelKey) -> ChannelKey {
    assert!(*key == FIRST);
    let mut bytes = [0x77; 32];
    bytes[..4].copy_from_slice(&0x0001_D29Au32.to_be_bytes());
    let second = ChannelKey(bytes);
    assert_eq!(
        mac.crypto().derive_channel_id(&second),
        mac.crypto().derive_channel_id(&FIRST)
    );
    second
}

fn channel_pairwise(mac: &ChannelMac, key: &ChannelKey) -> PairwiseKeys {
    let derived = mac.crypto().derive_channel_keys(key);
    PairwiseKeys {
        k_enc: derived.k_enc,
        k_mic: derived.k_mic,
    }
}

/// The key of the channel each delivered frame was reported on.
fn receive_channel_keys(mac: &mut ChannelMac) -> std::vec::Vec<ChannelKey> {
    let mut keys = std::vec::Vec::new();
    block_on(mac.receive_one(|_, event| {
        if let MacEventRef::Received(packet) = event {
            keys.push(*packet.channel().unwrap().key);
        }
    }))
    .unwrap();
    keys.dedup();
    keys
}

/// Both keys stay configured whichever is added first, and a multicast is
/// delivered on the channel whose key sealed it, including when the first
/// candidate tried fails. Each channel keeps its own replay window, so one
/// sender's equal counters on the two channels are both accepted.
#[test]
fn a_multicast_opens_under_whichever_colliding_key_sealed_it() {
    let probe = make_channel_mac();
    let second = colliding_key(&probe, &FIRST);
    for order in [[FIRST, second], [second, FIRST]] {
        let mut mac = make_channel_mac();
        mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
        let remote = test_pubkey(0xAB);
        mac.add_peer(remote).unwrap();
        for key in order {
            mac.add_channel(key).unwrap();
        }
        assert_eq!(mac.channels().len(), 2);

        for key in [FIRST, second] {
            let frame = multicast_frame(&mac, &remote, &key, 11);
            mac.radio_mut().queue_received_frame(&frame);
            assert_eq!(receive_channel_keys(&mut mac), [key], "{order:02x?}");
        }

        // The same frame again is a replay on its own channel.
        let frame = multicast_frame(&mac, &remote, &FIRST, 11);
        mac.radio_mut().queue_received_frame(&frame);
        assert!(receive_channel_keys(&mut mac).is_empty());
    }
}

/// A send names its channel by key and is sealed under exactly that key.
#[test]
fn a_multicast_is_sealed_under_the_key_it_names() {
    let mut mac = make_channel_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let second = colliding_key(&mac, &FIRST);
    mac.add_channel(FIRST).unwrap();
    mac.add_channel(second).unwrap();

    for (sent, other) in [(FIRST, second), (second, FIRST)] {
        mac.queue_multicast(local_id, &sent, b"hello", &SendOptions::default())
            .unwrap();
        let mut frame = mac.tx_queue_mut().pop_next().unwrap().frame;
        let header = PacketHeader::parse(frame.as_slice()).unwrap();
        let engine = mac.crypto();
        let wrong = channel_pairwise(&mac, &other);
        assert!(
            engine
                .open_packet(frame.as_mut_slice(), &header, &wrong, None)
                .is_err()
        );
        let right = channel_pairwise(&mac, &sent);
        assert!(
            engine
                .open_packet(frame.as_mut_slice(), &header, &right, None)
                .is_ok()
        );
    }
}

/// Operating policies follow the key, not the identifier the two share.
#[test]
fn colliding_channels_keep_their_own_policies() {
    let mut mac = make_channel_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let second = colliding_key(&mac, &FIRST);
    mac.add_channel(FIRST).unwrap();
    mac.add_channel(second).unwrap();
    mac.operating_policy_mut()
        .channel_policies
        .push(ChannelPolicy {
            channel_key: FIRST,
            require_unencrypted: true,
            require_full_source: false,
            max_flood_hops: None,
        })
        .unwrap();

    let encrypted = SendOptions::default();
    assert_eq!(
        mac.queue_multicast(local_id, &FIRST, b"hello", &encrypted),
        Err(SendError::PolicyViolation)
    );
    mac.queue_multicast(local_id, &second, b"hello", &encrypted)
        .unwrap();
}

/// A blind unicast is delivered over either colliding channel, reported on
/// the key that opened it.
#[test]
fn a_blind_unicast_opens_under_either_colliding_key() {
    let mut mac = make_channel_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let remote = test_pubkey(0xAB);
    let peer_id = mac.add_peer(remote).unwrap();
    let pairwise = PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    };
    mac.install_pairwise_keys(local_id, peer_id, pairwise.clone())
        .unwrap();
    let second = colliding_key(&mac, &FIRST);
    mac.add_channel(FIRST).unwrap();
    mac.add_channel(second).unwrap();
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    for (counter, key) in [(1, second), (2, FIRST)] {
        let frame = blind_frame(&mac, Ok(&remote), dst, &pairwise, &key, counter);
        mac.radio_mut().queue_received_frame(&frame);
        assert_eq!(receive_channel_keys(&mut mac), [key]);
    }
}

/// Two known peers share the source hint of a blind unicast, and the one
/// that sent it is tried second. The failed first attempt leaves the frame
/// as it found it, so the second opens it.
#[test]
fn a_blind_unicast_opens_for_the_second_peer_sharing_its_hint() {
    let mut mac = make_channel_mac();
    let local_id = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    // A key and its negation share a hint, and both are valid keys.
    let decoy = test_pubkey(0xAB);
    let mut sender = decoy.0;
    sender[31] ^= 0x80;
    let sender = PublicKey(sender);
    assert_eq!(decoy.hint(), sender.hint());
    for (peer, fill) in [(decoy, 3), (sender, 5)] {
        let peer_id = mac.add_peer(peer).unwrap();
        let keys = PairwiseKeys {
            k_enc: [fill; 32],
            k_mic: [fill + 1; 32],
        };
        mac.install_pairwise_keys(local_id, peer_id, keys).unwrap();
    }
    mac.add_channel(FIRST).unwrap();
    let dst = mac
        .identity(local_id)
        .unwrap()
        .identity()
        .public_key()
        .hint();

    let pairwise = PairwiseKeys {
        k_enc: [5; 32],
        k_mic: [6; 32],
    };
    let frame = blind_frame(&mac, Err(sender.hint()), dst, &pairwise, &FIRST, 1);
    mac.radio_mut().queue_received_frame(&frame);

    let mut delivered = std::vec::Vec::new();
    block_on(mac.receive_one(|_, event| {
        if let MacEventRef::Received(packet) = event {
            delivered.push(packet.payload_bytes().to_vec());
        }
    }))
    .unwrap();
    assert_eq!(delivered, [b"hello".to_vec()]);
}
