//! MAC ack authentication (security.md § Ack Tag Construction,
//! ack-transition.md). The destination seals its ack under the keys of the
//! request it answers; the sender completes a send only on an ack that
//! verifies under a construction the ack's options allow.

use super::*;
use umsh_crypto::AckTagConstruction;

/// The test platform, with real AES where it is available. The stub cipher
/// is a plain XOR, under which CMAC is linear: a tag under other keys or
/// over altered options can verify by accident, so the tests that need a
/// forgery to fail run only with `software-crypto`.
struct AckPlatform;

impl Platform for AckPlatform {
    type Identity = DummyIdentity;
    #[cfg(feature = "software-crypto")]
    type Aes = umsh_crypto::software::SoftwareAes;
    #[cfg(not(feature = "software-crypto"))]
    type Aes = DummyAes;
    type Sha = DummySha;
    type Radio = DummyRadio;
    type Delay = DummyDelay;
    type Clock = DummyClock;
    type Rng = DummyRng;
    type CounterStore = DummyCounterStore;
    type KeyValueStore = DummyKeyValueStore;
}

type AckMac = Mac<
    AckPlatform,
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

fn make_ack_mac() -> AckMac {
    #[cfg(feature = "software-crypto")]
    let aes = umsh_crypto::software::SoftwareAes;
    #[cfg(not(feature = "software-crypto"))]
    let aes = DummyAes;
    Mac::new(
        DummyRadio::default(),
        CryptoEngine::new(aes, DummySha),
        DummyClock {
            now_ms: Cell::new(123),
        },
        DummyRng(7),
        DummyCounterStore::default(),
        RepeaterConfig::default(),
        OperatingPolicy::default(),
    )
}

fn keys() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [1; 32],
        k_mic: [2; 32],
    }
}

fn callsign(text: &str) -> HamAddr {
    HamAddr::try_from_callsign(text).unwrap()
}

/// A node with identity `seed` that shares [`keys`] with `peer`.
fn endpoint(seed: u8, peer: &DummyIdentity) -> (AckMac, LocalIdentityId) {
    let mut mac = make_ack_mac();
    let local_id = mac.add_identity(DummyIdentity::new([seed; 32])).unwrap();
    let peer_id = mac.add_peer(*peer.public_key()).unwrap();
    mac.install_pairwise_keys(local_id, peer_id, keys())
        .unwrap();
    (mac, local_id)
}

fn repeater(seed: u8) -> AckMac {
    let mut mac = make_ack_mac();
    mac.repeater_config_mut().enabled = true;
    mac.add_identity(DummyIdentity::new([seed; 32])).unwrap();
    mac
}

fn frame_bytes(queued: QueuedTx) -> Vec<u8> {
    queued.frame.iter().copied().collect()
}

/// What `repeater` transmits after hearing `frame`, if anything.
fn forward(repeater: &mut AckMac, frame: &[u8]) -> Option<Vec<u8>> {
    repeater.radio_mut().queue_received_frame(frame);
    block_on(repeater.receive_one(|_, _| {})).unwrap();
    repeater.tx_queue_mut().pop_next().map(frame_bytes)
}

fn options(frame: &[u8]) -> ParsedOptions {
    let header = PacketHeader::parse(frame).unwrap();
    ParsedOptions::extract(frame, header.options_range).unwrap()
}

fn trailer(frame: &[u8]) -> [u8; 8] {
    frame[frame.len() - 8..].try_into().unwrap()
}

fn has_option(frame: &[u8], wanted: OptionNumber) -> bool {
    let header = PacketHeader::parse(frame).unwrap();
    iter_options(frame, header.options_range)
        .filter_map(Result::ok)
        .any(|(number, _)| OptionNumber::from(number) == wanted)
}

/// Alice, with one ack-requested send to Bob outstanding.
struct Sender {
    mac: AckMac,
    local_id: LocalIdentityId,
    receipt: SendReceipt,
    request: Vec<u8>,
}

impl Sender {
    fn new(send_options: SendOptions) -> Self {
        Self::configured(send_options, |_| {})
    }

    fn configured(send_options: SendOptions, configure: impl FnOnce(&mut AckMac)) -> Self {
        let bob = DummyIdentity::new([0x20; 32]);
        let (mut mac, local_id) = endpoint(0x10, &bob);
        configure(&mut mac);
        let receipt = block_on(mac.send_unicast(
            local_id,
            bob.public_key(),
            b"hello",
            &send_options.with_ack_requested(true),
        ))
        .unwrap()
        .unwrap();
        let request = frame_bytes(mac.tx_queue_mut().pop_next().expect("queued request"));
        Self {
            mac,
            local_id,
            receipt,
            request,
        }
    }

    fn pending(&self) -> &PendingAck {
        self.mac
            .identity(self.local_id)
            .unwrap()
            .pending_ack(&self.receipt)
            .expect("the send is outstanding")
    }

    /// Whether hearing `ack` completes the send.
    fn completes(&mut self, ack: &[u8]) -> bool {
        self.mac.radio_mut().queue_received_frame(ack);
        let mut acked = None;
        block_on(self.mac.receive_one(|_, event| {
            if let MacEventRef::AckReceived { receipt, .. } = event {
                acked = Some(receipt);
            }
        }))
        .unwrap();
        acked == Some(self.receipt)
    }
}

/// Bob, configured by `configure`, receiving `request` and returning the
/// acknowledgment he queues.
fn bob_acks(request: &[u8], configure: impl FnOnce(&mut AckMac)) -> Vec<u8> {
    let alice = DummyIdentity::new([0x10; 32]);
    let (mut bob, _) = endpoint(0x20, &alice);
    configure(&mut bob);
    bob.radio_mut().queue_received_frame(request);
    assert!(block_on(bob.receive_one(|_, _| {})).unwrap());
    let ack = frame_bytes(bob.tx_queue_mut().pop_next().expect("queued ack"));
    let header = PacketHeader::parse(&ack).unwrap();
    assert_eq!(header.packet_type(), PacketType::MacAck);
    ack
}

/// With nothing static to cover, an ack keeps the tag a node that
/// predates the MIC can check, and marks it.
#[test]
fn an_ack_with_no_static_option_keeps_the_legacy_tag_and_says_so() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = bob_acks(&alice.request, |_| {});

    let parsed = options(&ack);
    assert!(parsed.legacy_ack_tag);
    assert!(!parsed.has_static);
    assert_eq!(trailer(&ack), alice.pending().ack_trailer);
    assert_eq!(
        alice
            .mac
            .crypto()
            .verify_mac_ack(&keys(), &alice.pending().ack_v, &ack),
        Some(AckTagConstruction::Legacy)
    );
    assert!(alice.completes(&ack));
}

/// An ack is a locally originated packet, so it carries the operator
/// callsign; that static option is sealed with the MIC.
#[test]
fn an_ack_carrying_the_operator_callsign_is_sealed_with_the_mic() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = bob_acks(&alice.request, |bob| {
        bob.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
    });

    let parsed = options(&ack);
    assert!(has_option(&ack, OptionNumber::OperatorCallsign));
    assert!(parsed.has_static);
    assert!(!parsed.legacy_ack_tag);
    let legacy = alice.pending().ack_trailer;
    assert_eq!(trailer(&ack)[..4], legacy[..4]);
    assert_ne!(trailer(&ack)[4..], legacy[4..]);
    assert_eq!(
        alice
            .mac
            .crypto()
            .verify_mac_ack(&keys(), &alice.pending().ack_v, &ack),
        Some(AckTagConstruction::Mic)
    );
    assert!(alice.completes(&ack));
}

#[derive(Clone, Copy, Debug)]
enum Tag {
    Legacy,
    Mic,
}

/// An ack answering `v`, with the options and tag construction given,
/// whatever the selection rule would have chosen.
fn forged_shape(alice: &Sender, with_callsign: bool, marker: bool, tag: Tag) -> Vec<u8> {
    let build = |marker: bool| {
        let mut buf = [0u8; 256];
        let mut placeholder = [0u8; 8];
        placeholder[..4].copy_from_slice(&alice.pending().ack_v[..4]);
        let mut builder = PacketBuilder::new(&mut buf).mac_ack(placeholder);
        if with_callsign {
            builder = builder.option(
                OptionNumber::OperatorCallsign,
                callsign("KZ2X").as_trimmed_slice(),
            );
        }
        if marker {
            builder = builder.legacy_ack_tag();
        }
        builder.build().unwrap().to_vec()
    };
    let crypto = alice.mac.crypto();
    let v = alice.pending().ack_v;
    let tag_bytes = match tag {
        Tag::Legacy => crypto.legacy_ack_tag(&keys().k_enc, &v),
        // The marker is dynamic, so the MIC of a frame without it is the
        // MIC of the same frame with it.
        Tag::Mic => {
            let mut unmarked = build(false);
            crypto.seal_mac_ack(&keys(), &v, &mut unmarked).unwrap();
            trailer(&unmarked)[4..].try_into().unwrap()
        }
    };
    let mut ack = build(marker);
    let len = ack.len();
    ack[len - 4..].copy_from_slice(&tag_bytes);
    ack
}

/// The receiver table of the transition appendix: the marker admits the
/// legacy tag only, a static option the MIC only, and neither both.
#[test]
fn the_sender_admits_only_the_construction_the_ack_options_allow() {
    let cases = [
        (false, false, Tag::Legacy, true),
        (false, false, Tag::Mic, true),
        (false, true, Tag::Legacy, true),
        (false, true, Tag::Mic, false),
        (true, false, Tag::Mic, true),
        (true, false, Tag::Legacy, false),
        (true, true, Tag::Legacy, true),
        (true, true, Tag::Mic, false),
    ];
    for (with_callsign, marker, tag, accepted) in cases {
        let mut alice = Sender::new(SendOptions::default().no_flood());
        let ack = forged_shape(&alice, with_callsign, marker, tag);
        assert_eq!(
            alice.completes(&ack),
            accepted,
            "callsign {with_callsign}, marker {marker}, {tag:?} tag"
        );
    }
}

/// The MIC covers the ack's static options: an altered callsign fails it,
/// and the send stays outstanding for the genuine ack.
#[cfg(feature = "software-crypto")]
#[test]
fn an_altered_static_option_fails_the_mic() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = bob_acks(&alice.request, |bob| {
        bob.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
    });
    let mut altered = ack.clone();
    let header = PacketHeader::parse(&altered).unwrap();
    altered[header.options_range.start + 1] ^= 0x01;

    assert!(!alice.completes(&altered));
    assert!(alice.completes(&ack));
}

/// An ack sealed under keys other than the request's is no proof of
/// delivery, even with the right `ack_mic`.
#[cfg(feature = "software-crypto")]
#[test]
fn an_ack_under_other_keys_completes_nothing() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = bob_acks(&alice.request, |bob| {
        bob.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
    });
    let mut resealed = ack.clone();
    let other = PairwiseKeys {
        k_enc: [3; 32],
        k_mic: [4; 32],
    };
    let v = alice.pending().ack_v;
    alice
        .mac
        .crypto()
        .seal_mac_ack(&other, &v, &mut resealed)
        .unwrap();

    assert!(!alice.completes(&resealed));
    assert!(alice.completes(&ack));
}

/// The marker is an ordinary non-critical option to a repeater, and what
/// a repeater adds is dynamic: a forwarded legacy ack still verifies.
#[test]
fn a_marked_ack_crosses_a_repeater_unchanged() {
    let mut alice = Sender::new(SendOptions::default().with_flood_hops(2));
    let mut relay = repeater(0x30);
    let request = forward(&mut relay, &alice.request).expect("the request is repeated");
    let ack = bob_acks(&request, |_| {});
    let forwarded = forward(&mut relay, &ack).expect("the ack is repeated");

    assert!(options(&forwarded).legacy_ack_tag);
    assert_eq!(trailer(&forwarded), trailer(&ack));
    assert!(alice.completes(&forwarded));
}

/// A Licensed-Only repeater carries only traffic that names its operator.
/// An ack now does, and the station callsign the repeater adds is
/// dynamic, so the ack still verifies on arrival.
#[test]
fn a_licensed_only_repeater_carries_a_callsign_ack_that_still_verifies() {
    let mut alice = Sender::configured(
        SendOptions::default().with_flood_hops(2).unencrypted(),
        |alice| alice.operating_policy_mut().operator_callsign = Some(callsign("KZ2X")),
    );
    let mut relay = repeater(0x30);
    relay.repeater_config_mut().amateur_radio_mode = AmateurRadioMode::LicensedOnly;
    relay.repeater_config_mut().station_callsign = Some(callsign("N0CALL"));

    let request = forward(&mut relay, &alice.request).expect("the request is repeated");
    let ack = bob_acks(&request, |bob| {
        bob.operating_policy_mut().operator_callsign = Some(callsign("KZ2Y"));
    });
    let forwarded = forward(&mut relay, &ack).expect("the ack is repeated");

    assert!(has_option(&forwarded, OptionNumber::StationCallsign));
    assert!(alice.completes(&forwarded));
}

/// A blind unicast's ack is sealed under the pairwise keys combined with
/// the channel's; the pairwise keys alone do not verify it.
#[cfg(feature = "software-crypto")]
#[test]
fn a_blind_unicast_ack_verifies_under_the_combined_keys() {
    let bob = DummyIdentity::new([0x20; 32]);
    let channel = ChannelKey([0x5A; 32]);
    let (mut alice, local_id) = endpoint(0x10, &bob);
    alice.add_channel(channel).unwrap();
    let channel_keys = alice.crypto().derive_channel_keys(&channel);
    let receipt = block_on(alice.send_blind_unicast(
        local_id,
        bob.public_key(),
        &channel_keys.channel_id,
        b"hello",
        &SendOptions::default().with_ack_requested(true).no_flood(),
    ))
    .unwrap()
    .unwrap();
    let request = frame_bytes(alice.tx_queue_mut().pop_next().expect("queued request"));
    let mut alice = Sender {
        mac: alice,
        local_id,
        receipt,
        request,
    };

    let ack = bob_acks(&alice.request, |bob| {
        bob.add_channel(channel).unwrap();
        bob.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
    });
    let blind = alice.mac.crypto().derive_blind_keys(&keys(), &channel_keys);
    let v = alice.pending().ack_v;
    assert_eq!(
        alice.mac.crypto().verify_mac_ack(&blind, &v, &ack),
        Some(AckTagConstruction::Mic)
    );
    assert_eq!(alice.mac.crypto().verify_mac_ack(&keys(), &v, &ack), None);
    assert!(alice.completes(&ack));
}
