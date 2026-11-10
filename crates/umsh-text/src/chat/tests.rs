use alloc::vec::Vec;

use umsh_core::{ChannelKey, ChannelTag, NodeHint, PublicKey};

use super::*;
use crate::codec;
use crate::engine::{ComposeIntent, DeliveryState, Destination, EngineConfig};

const LOCAL: PublicKey = PublicKey([0xAA; 32]);
const PEER: PublicKey = PublicKey([0x11; 32]);
const OTHER: PublicKey = PublicKey([0x22; 32]);
const CHANNEL: ChannelTag = ChannelTag([0x07; 16]);
const CHANNEL_KEY: ChannelKey = ChannelKey([0x42; 32]);

fn seeds(session_id: u64) -> Seeds {
    Seeds {
        session_id,
        jitter_seed: session_id,
    }
}

fn facade(local_key: PublicKey, session_id: u64) -> ChatFacade {
    let mut facade = ChatFacade::new(
        DirectChannelProfile,
        local_key,
        EngineConfig::default(),
        seeds(session_id),
    );
    facade.channels_mut().register(CHANNEL, CHANNEL_KEY, None);
    facade
}

fn text(body: &str) -> ComposeIntent<'_> {
    ComposeIntent::Text {
        body,
        status: false,
    }
}

fn direct() -> ConversationKey {
    ConversationKey::Direct { peer: PEER }
}

fn group() -> ConversationKey {
    ConversationKey::ChannelGroup { channel: CHANNEL }
}

fn insert(mutations: &[Mutation]) -> &Insert {
    mutations
        .iter()
        .find_map(|mutation| match &mutation.change {
            Change::Insert(insert) => Some(insert),
            _ => None,
        })
        .expect("an insert")
}

fn inserts(outputs: &[ChatOutput]) -> Vec<&Insert> {
    outputs
        .iter()
        .filter_map(|output| match output {
            ChatOutput::Mutation(Mutation {
                change: Change::Insert(insert),
                ..
            }) => Some(insert),
            _ => None,
        })
        .collect()
}

fn resolutions(outputs: &[ChatOutput]) -> Vec<SenderResolution> {
    outputs
        .iter()
        .filter_map(|output| match output {
            ChatOutput::SenderResolved(resolution) => Some(*resolution),
            _ => None,
        })
        .collect()
}

fn deliveries(outputs: &[ChatOutput]) -> Vec<Delivery> {
    outputs
        .iter()
        .filter_map(|output| match output {
            ChatOutput::Delivery(delivery) => Some(*delivery),
            _ => None,
        })
        .collect()
}

/// The payload of a group message `sender` composes and commits.
fn group_payload(sender: &mut ChatFacade, body: &str, token: u32) -> Vec<u8> {
    let batch = sender.compose(group(), token, text(body), None, 0).unwrap();
    let outbound = sender.commit(batch).unwrap();
    outbound.transmissions()[0].payload.to_vec()
}

/// A composed batch holds its frames, and only committing it releases them.
#[test]
fn committing_a_batch_releases_its_frames() {
    let mut chat = facade(LOCAL, 1);
    let batch = chat.compose(direct(), 7, text("hello"), None, 0).unwrap();
    assert_eq!(batch.checkpoint.conversation, direct());
    assert_eq!(batch.archives.len(), 1);
    assert_eq!(batch.transmission_count(), 1);
    let insert = insert(&batch.mutations);
    assert_eq!(insert.direction, Direction::Outbound);
    assert_eq!(insert.client_token, Some(7));
    assert_eq!(insert.body, "hello");
    // Nothing reaches a drain while the batch is pending.
    assert!(chat.drain().is_empty());
    assert!(chat.has_pending_batch());

    let outbound = chat.commit(batch).unwrap();
    assert_eq!(outbound.session_id(), 1);
    assert_eq!(outbound.len(), 1);
    assert_eq!(
        outbound.transmissions()[0].destination,
        Destination::Peer(PEER)
    );
    assert!(!chat.has_pending_batch());
}

/// Rejecting rebuilds the engine, which would strand a second batch's
/// frames, so a second compose waits for the first batch to settle.
#[test]
fn one_batch_is_outstanding_at_a_time() {
    let mut chat = facade(LOCAL, 1);
    let first = chat.compose(direct(), 1, text("one"), None, 0).unwrap();
    assert_eq!(
        chat.compose(direct(), 2, text("two"), None, 0).unwrap_err(),
        ChatComposeError::BatchPending
    );
    chat.commit(first).unwrap();
    let second = chat.compose(direct(), 2, text("two"), None, 1).unwrap();
    assert_ne!(second.id(), 0);
    chat.commit(second).unwrap();
}

/// A batch from another facade is refused rather than released.
#[test]
fn a_foreign_batch_is_refused() {
    let mut chat = facade(LOCAL, 1);
    let mut other = facade(LOCAL, 2);
    let ours = chat.compose(direct(), 1, text("ours"), None, 0).unwrap();
    let theirs = other.compose(direct(), 1, text("theirs"), None, 0).unwrap();
    // Both are batch 1 of their facades, but only one is pending here.
    assert_eq!(chat.commit(ours).map(|out| out.len()), Ok(1));
    assert_eq!(chat.commit(theirs).unwrap_err(), BatchMismatch);
}

/// Rejecting fails the batch's frames and restores the engine from the
/// supplied checkpoints: the rejected message's wire ID was never used, so
/// the next message takes it.
#[test]
fn rejecting_fails_frames_and_restores_from_checkpoints() {
    let mut chat = facade(LOCAL, 1);
    let stored = chat.compose(direct(), 1, text("kept"), None, 0).unwrap();
    let checkpoint = stored.checkpoint;
    chat.commit(stored).unwrap();

    let lost = chat.compose(direct(), 2, text("lost"), None, 1).unwrap();
    let lost_handle = lost.mutations[0].handle;
    let lost_wire = insert(&lost.mutations).wire_id;
    let drain = chat.reject(lost, &[checkpoint], seeds(2), 2).unwrap();

    // The failure is reported under the session that composed it, as
    // undelivered: nothing of it went out.
    assert_eq!(drain.session_id, 1);
    assert!(drain.outbound.is_empty());
    assert_eq!(
        deliveries(&drain.outputs),
        [Delivery {
            handle: lost_handle,
            fragment: None,
            fragments: 1,
            state: DeliveryState::Undelivered,
            via_flood: false,
        }]
    );
    assert_eq!(chat.session_id(), 2);
    assert!(!chat.has_pending_batch());

    let next = chat.compose(direct(), 3, text("again"), None, 3).unwrap();
    assert_eq!(next.session_id(), 2);
    assert_eq!(insert(&next.mutations).wire_id, lost_wire);
    assert_eq!(next.checkpoint, checkpoint_after(&checkpoint));
}

fn checkpoint_after(checkpoint: &StreamCheckpoint) -> StreamCheckpoint {
    StreamCheckpoint {
        next_id: checkpoint.next_id.wrapping_add(1),
        ..*checkpoint
    }
}

/// The local Sender Handle belongs to the session, not the engine, and a
/// rebuilt engine still names us on group messages.
#[test]
fn rejecting_keeps_the_sender_handle() {
    let mut chat = facade(LOCAL, 1);
    chat.set_local_handle("Ada");
    let lost = chat.compose(group(), 1, text("lost"), None, 0).unwrap();
    let checkpoints = [];
    let _ = chat.reject(lost, &checkpoints, seeds(2), 1).unwrap();
    assert_eq!(chat.local_handle(), "Ada");

    let batch = chat.compose(group(), 2, text("still me"), None, 2).unwrap();
    let outbound = chat.commit(batch).unwrap();
    let payload = &outbound.transmissions()[0].payload;
    let message = codec::parse(payload).unwrap();
    assert_eq!(message.sender_handle, Some("Ada"));
}

/// Delivery reports for frames of an engine since rebuilt are ignored: the
/// rebuilt engine reissues transmission IDs, so applying one would mark an
/// unrelated frame.
#[test]
fn reports_for_a_rejected_session_are_ignored() {
    let mut chat = facade(LOCAL, 1);
    let batch = chat.compose(direct(), 1, text("first"), None, 0).unwrap();
    let old = chat.commit(batch).unwrap();
    let old_id = old.transmissions()[0].transmission_id;

    let lost = chat.compose(direct(), 2, text("lost"), None, 1).unwrap();
    let _ = chat.reject(lost, &[], seeds(2), 2).unwrap();
    let batch = chat.compose(direct(), 3, text("new"), None, 3).unwrap();
    let new = chat.commit(batch).unwrap();
    assert_eq!(new.transmissions()[0].transmission_id, old_id);

    chat.transmit_update(old.session_id(), old_id, TransmitUpdate::Failed, 4);
    assert!(chat.drain().outputs.is_empty());
    chat.transmit_update(
        new.session_id(),
        old_id,
        TransmitUpdate::Acked { via_flood: true },
        5,
    );
    let delivered = deliveries(&chat.drain().outputs);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].state, DeliveryState::Acked);
    assert!(delivered[0].via_flood);
}

/// The first full key seen for a member's hint wins and is announced once,
/// ahead of the message that carried it; later frames under that hint are
/// attributed to it whether or not they carry a key.
#[test]
fn the_first_key_for_a_hint_resolves_it_once() {
    let mut member = facade(PEER, 9);
    member.set_local_handle("Bea");
    let hint = NodeHint([PEER.0[0], PEER.0[1], PEER.0[2]]);
    let mut chat = facade(LOCAL, 1);

    let first = group_payload(&mut member, "one", 1);
    let source = TextSource::ChannelGroup {
        channel: CHANNEL,
        hint,
        full_key: Some(PEER),
    };
    chat.receive(source, &first, 10).unwrap();
    let drain = chat.drain();
    assert_eq!(
        resolutions(&drain.outputs),
        [SenderResolution {
            channel: CHANNEL,
            hint,
            key: PEER,
        }]
    );
    assert!(matches!(drain.outputs[0], ChatOutput::SenderResolved(_)));
    let received = inserts(&drain.outputs);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].sender, SenderScope::ClaimedMember(hint));
    assert_eq!(received[0].sender_key, Some(PEER));
    assert_eq!(received[0].sender_handle.as_deref(), Some("Bea"));

    // Another key claiming the same hint neither displaces nor re-announces.
    let second = group_payload(&mut member, "two", 2);
    let source = TextSource::ChannelGroup {
        channel: CHANNEL,
        hint,
        full_key: Some(OTHER),
    };
    chat.receive(source, &second, 11).unwrap();
    let drain = chat.drain();
    assert!(resolutions(&drain.outputs).is_empty());
    assert_eq!(inserts(&drain.outputs)[0].sender_key, Some(PEER));

    // A frame naming only the hint is still attributed.
    let third = group_payload(&mut member, "three", 3);
    let source = TextSource::ChannelGroup {
        channel: CHANNEL,
        hint,
        full_key: None,
    };
    chat.receive(source, &third, 12).unwrap();
    let drain = chat.drain();
    assert!(resolutions(&drain.outputs).is_empty());
    assert_eq!(inserts(&drain.outputs)[0].sender_key, Some(PEER));
    assert_eq!(chat.member_key(&CHANNEL, &hint), Some(PEER));
}

/// Resolved members are the session's, and survive a rebuilt engine without
/// being announced again.
#[test]
fn resolved_members_survive_a_rejected_batch() {
    let mut member = facade(PEER, 9);
    let hint = NodeHint([PEER.0[0], PEER.0[1], PEER.0[2]]);
    let mut chat = facade(LOCAL, 1);
    let source = TextSource::ChannelGroup {
        channel: CHANNEL,
        hint,
        full_key: Some(PEER),
    };
    let payload = group_payload(&mut member, "hi", 1);
    chat.receive(source, &payload, 0).unwrap();
    assert_eq!(resolutions(&chat.drain().outputs).len(), 1);

    let lost = chat.compose(group(), 1, text("lost"), None, 1).unwrap();
    let _ = chat.reject(lost, &[], seeds(2), 2).unwrap();
    assert_eq!(chat.member_key(&CHANNEL, &hint), Some(PEER));

    let payload = group_payload(&mut member, "again", 2);
    chat.receive(source, &payload, 3).unwrap();
    let drain = chat.drain();
    assert!(resolutions(&drain.outputs).is_empty());
    assert_eq!(inserts(&drain.outputs)[0].sender_key, Some(PEER));
}

/// A channel the session does not hold takes no traffic.
#[test]
fn a_channel_not_held_is_refused() {
    let mut member = facade(PEER, 9);
    let payload = group_payload(&mut member, "hi", 1);
    let mut chat = facade(LOCAL, 1);
    chat.channels_mut().remove(&CHANNEL);
    let source = TextSource::ChannelGroup {
        channel: CHANNEL,
        hint: NodeHint([1, 2, 3]),
        full_key: Some(PEER),
    };
    assert_eq!(
        chat.receive(source, &payload, 0),
        Err(ChatReceiveError::ChannelNotHeld)
    );
    assert!(chat.drain().is_empty());
    assert_eq!(chat.member_key(&CHANNEL, &NodeHint([1, 2, 3])), None);
}

/// Radio metadata belongs on records describing received content only.
#[test]
fn only_received_content_describes_a_receipt() {
    let mut sender = facade(PEER, 9);
    let batch = sender
        .compose(
            ConversationKey::Direct { peer: LOCAL },
            1,
            text("hi"),
            None,
            0,
        )
        .unwrap();
    let payload = sender.commit(batch).unwrap().transmissions()[0]
        .payload
        .to_vec();

    let mut chat = facade(LOCAL, 1);
    chat.receive(TextSource::Direct { peer: PEER }, &payload, 0)
        .unwrap();
    let drain = chat.drain();
    let received = drain
        .outputs
        .iter()
        .find_map(|output| match output {
            ChatOutput::Mutation(mutation) => Some(mutation),
            _ => None,
        })
        .unwrap();
    assert!(received.describes_receipt());

    let batch = chat.compose(direct(), 1, text("mine"), None, 1).unwrap();
    assert!(!batch.mutations[0].describes_receipt());
    chat.commit(batch).unwrap();
}

/// The channel registry resolves a frame's authenticating key to the
/// conversation's tag, and nothing else.
#[test]
fn the_registry_maps_keys_to_tags() {
    let mut registry = ChannelRegistry::default();
    registry.register(CHANNEL, CHANNEL_KEY, Some(3));
    assert_eq!(registry.tag_for(&CHANNEL_KEY), Some(CHANNEL));
    assert_eq!(registry.tag_for(&ChannelKey([0x43; 32])), None);
    assert_eq!(registry.max_flood_hops(&CHANNEL), Some(3));
    registry.remove(&CHANNEL);
    assert_eq!(registry.tag_for(&CHANNEL_KEY), None);
}

#[test]
fn a_zero_session_id_is_taken_as_one() {
    let chat = facade(LOCAL, 0);
    assert_eq!(chat.session_id(), 1);
}
