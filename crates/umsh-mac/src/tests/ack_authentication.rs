//! MAC ack authentication (security.md § Ack Tag Construction). The
//! destination seals its ack under the keys of the request it answers; the
//! sender completes a send only on an ack whose MIC verifies.

use super::*;

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

/// With nothing static to cover, an ack's tag still covers its header:
/// `AAD_ack` is the FCF and the terminator.
#[test]
fn an_ack_with_no_static_option_is_sealed_with_the_mic() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = bob_acks(&alice.request, |_| {});

    assert!(!options(&ack).has_static);
    let v = alice.pending().ack_v;
    assert_eq!(trailer(&ack)[..4], v[..4]);
    assert!(alice.mac.crypto().verify_mac_ack(&keys(), &v, &ack));
    assert!(alice.completes(&ack));
}

/// An ack is a locally originated packet, so it carries the operator
/// callsign; the MIC covers that static option.
#[test]
fn an_ack_carrying_the_operator_callsign_is_sealed_with_the_mic() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = bob_acks(&alice.request, |bob| {
        bob.operating_policy_mut().operator_callsign = Some(callsign("KZ2X"));
    });

    assert!(has_option(&ack, OptionNumber::OperatorCallsign));
    assert!(options(&ack).has_static);
    let v = alice.pending().ack_v;
    assert_eq!(trailer(&ack)[..4], v[..4]);
    assert!(alice.mac.crypto().verify_mac_ack(&keys(), &v, &ack));
    assert!(alice.completes(&ack));
}

/// An ack answering the outstanding send, carrying `options`, sealed under
/// [`keys`].
fn sealed_ack(alice: &Sender, options: &[(OptionNumber, &[u8])]) -> Vec<u8> {
    let v = alice.pending().ack_v;
    let mut buf = [0u8; 256];
    let mut placeholder = [0u8; 8];
    placeholder[..4].copy_from_slice(&v[..4]);
    let mut builder = PacketBuilder::new(&mut buf).mac_ack(placeholder);
    for &(number, value) in options {
        builder = builder.option(number, value);
    }
    let mut ack = builder.build().unwrap().to_vec();
    alice
        .mac
        .crypto()
        .seal_mac_ack(&keys(), &v, &mut ack)
        .unwrap();
    ack
}

/// An ack delivers nothing, so a delivery-critical option it does not
/// recognize does not refuse it; the MIC still covers that option.
#[test]
fn an_ack_with_an_unknown_delivery_critical_option_is_accepted() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = sealed_ack(&alice, &[(OptionNumber::Unknown(12), &[0xA5, 0x5A])]);
    assert!(options(&ack).has_unknown_delivery_critical);
    assert!(alice.completes(&ack));
}

/// A wrong tag completes nothing, and the send stays outstanding.
#[test]
fn an_ack_with_a_wrong_tag_completes_nothing() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = sealed_ack(&alice, &[]);
    let mut forged = ack.clone();
    let len = forged.len();
    forged[len - 1] ^= 0x01;

    assert!(!alice.completes(&forged));
    assert!(alice.completes(&ack));
}

#[cfg(feature = "software-crypto")]
#[test]
fn an_altered_unknown_delivery_critical_option_fails_the_mic() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let ack = sealed_ack(&alice, &[(OptionNumber::Unknown(12), &[0xA5, 0x5A])]);
    let mut altered = ack.clone();
    let header = PacketHeader::parse(&altered).unwrap();
    altered[header.options_range.start + 1] ^= 0x01;

    assert!(!alice.completes(&altered));
    assert!(alice.completes(&ack));
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

/// What a repeater adds is dynamic, so a forwarded ack keeps its tag and
/// still verifies.
#[test]
fn an_ack_crosses_a_repeater_and_still_verifies() {
    let mut alice = Sender::new(SendOptions::default().with_flood_hops(2));
    let mut relay = repeater(0x30);
    let request = forward(&mut relay, &alice.request).expect("the request is repeated");
    let ack = bob_acks(&request, |_| {});
    let forwarded = forward(&mut relay, &ack).expect("the ack is repeated");

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

/// A repeater forwards an ack carrying the fence, the fence goes on with
/// it, and the ack still verifies.
#[test]
fn a_repeater_forwards_the_fence() {
    let mut alice = Sender::new(SendOptions::default().no_flood());
    let v = alice.pending().ack_v;
    let mut buf = [0u8; 256];
    let mut placeholder = [0u8; 8];
    placeholder[..4].copy_from_slice(&v[..4]);
    let mut ack = PacketBuilder::new(&mut buf)
        .mac_ack(placeholder)
        .flood_hops(2)
        .option(OptionNumber::Fence, &[])
        .build()
        .unwrap()
        .to_vec();
    alice
        .mac
        .crypto()
        .seal_mac_ack(&keys(), &v, &mut ack)
        .unwrap();

    let mut relay = repeater(0x30);
    let forwarded = forward(&mut relay, &ack).expect("the ack is repeated");
    assert!(has_option(&forwarded, OptionNumber::Fence));
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
        &channel,
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
    assert!(alice.mac.crypto().verify_mac_ack(&blind, &v, &ack));
    assert!(!alice.mac.crypto().verify_mac_ack(&keys(), &v, &ack));
    assert!(alice.completes(&ack));
}
