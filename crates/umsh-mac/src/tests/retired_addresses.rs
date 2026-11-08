//! Retired addresses: traffic for an address the MAC holds no key for is
//! reported once both of its ends match, and is neither delivered nor
//! carried on.

use super::*;

const CHANNEL_KEY: ChannelKey = ChannelKey([0x5A; 32]);

/// Keys the sender seals with. The receiver never has them, which is the
/// point: a retired address's keys are gone.
fn session_keys() -> PairwiseKeys {
    PairwiseKeys {
        k_enc: [3; 32],
        k_mic: [4; 32],
    }
}

/// A MAC with one long-term identity watching `retired` for traffic from
/// `peer`.
fn watching(retired: &PublicKey, peer: &PublicKey) -> (TestMac, LocalIdentityId) {
    let mut mac = make_mac();
    let parent = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    mac.watch_retired_address(parent, *retired, *peer).unwrap();
    (mac, parent)
}

/// Every retired address reported, with the identity it was reported on.
fn heard(mac: &mut TestMac) -> (bool, std::vec::Vec<(LocalIdentityId, PublicKey)>) {
    let mut seen = std::vec::Vec::new();
    let handled = block_on(mac.receive_one(|identity, event| {
        if let MacEventRef::RetiredAddressHeard { address } = event {
            seen.push((identity, address));
        }
    }))
    .unwrap();
    (handled, seen)
}

#[test]
fn unicast_to_a_retired_address_is_reported_on_its_parent() {
    let retired = test_pubkey(0x31);
    let peer = DummyIdentity::new([0x42; 32]);
    let (mut mac, parent) = watching(&retired, peer.public_key());

    mac.radio_mut().queue_received_unicast(
        &peer,
        &session_keys(),
        &retired.hint(),
        &[1, 0x44],
        true,
    );

    let (handled, seen) = heard(&mut mac);
    assert!(handled);
    assert_eq!(seen, [(parent, retired)]);
    assert!(
        mac.tx_queue_mut().pop_next().is_none(),
        "nothing is acknowledged or carried on"
    );
}

#[test]
fn unicast_from_a_peer_named_by_hint_is_reported() {
    let retired = test_pubkey(0x31);
    let peer = test_pubkey(0x42);
    let (mut mac, parent) = watching(&retired, &peer);

    mac.radio_mut().queue_received_unicast_with_source_hint(
        peer.hint(),
        &session_keys(),
        &retired.hint(),
        &[1, 0x44],
        false,
    );

    assert_eq!(heard(&mut mac).1, [(parent, retired)]);
}

#[test]
fn blind_unicast_to_a_retired_address_is_reported() {
    let retired = test_pubkey(0x31);
    let peer = DummyIdentity::new([0x42; 32]);
    let (mut mac, parent) = watching(&retired, peer.public_key());
    mac.add_channel(CHANNEL_KEY).unwrap();
    let channel_keys = mac.crypto().derive_channel_keys(&CHANNEL_KEY);

    mac.radio_mut().queue_received_blind_unicast(
        &peer,
        &session_keys(),
        &channel_keys,
        &retired.hint(),
        &[1, 0x44],
        false,
    );

    let (handled, seen) = heard(&mut mac);
    assert!(handled);
    assert_eq!(seen, [(parent, retired)]);
}

#[test]
fn a_stranger_writing_to_a_retired_address_is_not_reported() {
    let retired = test_pubkey(0x31);
    let peer = test_pubkey(0x42);
    let stranger = DummyIdentity::new([0x43; 32]);
    let (mut mac, _) = watching(&retired, &peer);

    mac.radio_mut().queue_received_unicast(
        &stranger,
        &session_keys(),
        &retired.hint(),
        &[1, 0x44],
        false,
    );

    assert!(heard(&mut mac).1.is_empty());
}

#[test]
fn a_live_identity_answers_before_a_retired_address() {
    let mut mac = make_mac();
    let parent = mac.add_identity(DummyIdentity::new([0x10; 32])).unwrap();
    let live = *mac.identity(parent).unwrap().identity().public_key();
    let peer = DummyIdentity::new([0x42; 32]);
    mac.watch_retired_address(parent, live, *peer.public_key())
        .unwrap();

    mac.radio_mut()
        .queue_received_unicast(&peer, &session_keys(), &live.hint(), &[1, 0x44], false);

    assert!(heard(&mut mac).1.is_empty());
}

#[test]
fn a_forgotten_address_is_not_reported() {
    let retired = test_pubkey(0x31);
    let peer = DummyIdentity::new([0x42; 32]);
    let (mut mac, _) = watching(&retired, peer.public_key());
    assert!(mac.forget_retired_address(&retired));
    assert!(!mac.forget_retired_address(&retired));

    mac.radio_mut().queue_received_unicast(
        &peer,
        &session_keys(),
        &retired.hint(),
        &[1, 0x44],
        false,
    );

    assert!(heard(&mut mac).1.is_empty());
    assert_eq!(mac.retired_addresses().count(), 0);
}

#[test]
fn watching_an_address_again_replaces_it() {
    let retired = test_pubkey(0x31);
    let (mut mac, parent) = watching(&retired, &test_pubkey(0x42));

    mac.watch_retired_address(parent, retired, test_pubkey(0x44))
        .unwrap();

    let watched: std::vec::Vec<_> = mac.retired_addresses().copied().collect();
    assert_eq!(
        watched,
        [RetiredAddress {
            parent,
            address: retired,
            peer: test_pubkey(0x44),
        }]
    );
}
