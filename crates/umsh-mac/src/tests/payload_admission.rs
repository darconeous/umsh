//! Payload admission: a destination with no room for a payload declines
//! the frame without acknowledging it or moving its window.

use super::*;

/// The payload type the admission below is asked about.
const CLAIMED: u8 = 3;

std::thread_local! {
    static ROOM: Cell<bool> = const { Cell::new(true) };
}

fn set_room(room: bool) {
    ROOM.with(|cell| cell.set(room));
}

/// Admits everything but [`CLAIMED`] payloads while there is no room.
fn admits(payload_type: u8) -> bool {
    payload_type != CLAIMED || ROOM.with(Cell::get)
}

/// A claimed payload, as it travels.
fn claimed(text: &[u8]) -> std::vec::Vec<u8> {
    let mut payload = std::vec![CLAIMED];
    payload.extend_from_slice(text);
    payload
}

/// A MAC with one keyed peer and the admission above installed.
fn admitting_mac() -> (
    TestMac,
    LocalIdentityId,
    DummyIdentity,
    PairwiseKeys,
    umsh_core::NodeHint,
) {
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
    mac.set_payload_admission(Some(admits));
    (mac, local_id, remote, keys, dst_hint)
}

fn last_accepted(mac: &TestMac, remote: &DummyIdentity) -> u32 {
    mac.rx_windows()
        .get(remote.public_key())
        .unwrap()
        .replay_window
        .last_accepted
}

fn mac_acks(queued: &[std::vec::Vec<u8>]) -> usize {
    queued
        .iter()
        .filter(|frame| {
            PacketHeader::parse(frame)
                .is_ok_and(|header| header.packet_type() == PacketType::MacAck)
        })
        .count()
}

#[test]
fn a_declined_frame_is_taken_on_retransmission_once_there_is_room() {
    let (mut mac, _, remote, keys, dst_hint) = admitting_mac();
    // Something earlier, so the window has a baseline to keep.
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        &claimed(b"first"),
        true,
        10,
    );
    let (delivered, _) = receive_and_collect(&mut mac);
    assert_eq!(delivered.len(), 1);
    let baseline = last_accepted(&mac, &remote);

    set_room(false);
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        &claimed(b"no room"),
        true,
        11,
    );
    let declined = last_queued_received(&mac);
    let (delivered, queued) = receive_and_collect(&mut mac);
    assert!(delivered.is_empty());
    assert!(queued.is_empty(), "a declined frame is not acknowledged");
    assert_eq!(mac.counters().rx_delivery_refused, 1);
    assert_eq!(last_accepted(&mac, &remote), baseline, "window untouched");

    // A frame of a type with no buffer behind it is not held back.
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        b"\x00other",
        true,
        12,
    );
    let (delivered, queued) = receive_and_collect(&mut mac);
    assert_eq!(delivered.len(), 1);
    assert_eq!(mac_acks(&queued), 1);

    // The sender's retransmission, once there is room, is new.
    set_room(true);
    mac.clock().advance_ms(10_000);
    mac.radio_mut().queue_received_frame(&declined);
    let (delivered, queued) = receive_and_collect(&mut mac);
    assert_eq!(delivered, [claimed(b"no room")]);
    assert_eq!(mac_acks(&queued), 1);
    assert_eq!(mac.counters().rx_delivery_refused, 1);
}

#[test]
fn a_duplicate_of_an_accepted_frame_is_reacked_while_admission_is_closed() {
    let (mut mac, _, remote, keys, dst_hint) = admitting_mac();
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        &claimed(b"taken"),
        true,
        10,
    );
    let taken = last_queued_received(&mac);
    let (delivered, queued) = receive_and_collect(&mut mac);
    assert_eq!(delivered.len(), 1);
    assert_eq!(mac_acks(&queued), 1);

    set_room(false);
    // Past the re-ack holdoff, so the copy reads as the sender's
    // retransmission: its first ack was lost.
    mac.clock().advance_ms(10_000);
    mac.radio_mut().queue_received_frame(&taken);
    let (delivered, queued) = receive_and_collect(&mut mac);
    set_room(true);
    assert!(delivered.is_empty(), "a duplicate is never delivered again");
    assert_eq!(mac_acks(&queued), 1, "but it is acknowledged again");
    assert_eq!(mac.counters().rx_delivery_refused, 0);
}

#[test]
fn a_declined_blind_unicast_leaves_the_window_alone() {
    let (mut mac, _, remote, pairwise, dst_hint) = admitting_mac();
    let channel_key = ChannelKey([0x5A; 32]);
    let channel_keys = mac.crypto().derive_channel_keys(&channel_key);
    mac.add_channel(channel_key).unwrap();

    set_room(false);
    mac.radio_mut().queue_received_blind_unicast(
        &remote,
        &pairwise,
        &channel_keys,
        &dst_hint,
        &claimed(b"blind"),
        true,
    );
    let declined = last_queued_received(&mac);
    let (delivered, queued) = receive_and_collect(&mut mac);
    set_room(true);
    assert!(delivered.is_empty());
    assert!(queued.is_empty());
    assert_eq!(mac.counters().rx_delivery_refused, 1);

    mac.radio_mut().queue_received_frame(&declined);
    let (delivered, queued) = receive_and_collect(&mut mac);
    assert_eq!(delivered, [claimed(b"blind")]);
    assert_eq!(mac_acks(&queued), 1);
}

/// A frame held while its sender vouches for it is asked about again when
/// the Frame Verified arrives: room may have gone while it waited, and the
/// answer's acknowledgment would stand for it.
#[test]
fn a_held_frame_is_declined_on_release_when_room_has_gone() {
    let (mut mac, _, remote, _, keys, dst_hint) = desynchronized_peer();
    mac.set_payload_admission(Some(admits));
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        &claimed(b"held"),
        true,
        7,
    );
    let _ = block_on(mac.receive_one(|_, _| {})).unwrap();
    let (nonce, _) = pop_verify_frame(&mut mac, &keys);
    let before = last_accepted(&mac, &remote);

    set_room(false);
    mac.radio_mut().queue_received_unicast_with_counter(
        &remote,
        &keys,
        &dst_hint,
        &frame_verified_payload(nonce),
        true,
        8,
    );
    let answer = last_queued_received(&mac);
    let (delivered, queued) = receive_and_collect(&mut mac);
    set_room(true);
    assert!(delivered.is_empty());
    assert!(queued.is_empty(), "the answer goes unacknowledged");
    assert_eq!(mac.counters().rx_delivery_refused, 1);
    assert_eq!(last_accepted(&mac, &remote), before, "window untouched");

    // The sender's next copy of the answer finds room and releases it.
    mac.radio_mut().queue_received_frame(&answer);
    let (delivered, queued) = receive_and_collect(&mut mac);
    assert_eq!(delivered, [claimed(b"held")]);
    assert_eq!(mac_acks(&queued), 1);
}
