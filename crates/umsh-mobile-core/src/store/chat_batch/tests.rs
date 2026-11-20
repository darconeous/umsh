use std::collections::HashMap;

use crate::mobile_chat::{
    MobileChatArchiveLookupRecord, MobileChatArchiveRecord, MobileChatCheckpointRecord,
    MobileChatComposeBatchRecord, MobileChatDeliveryState, MobileChatDirection,
    MobileChatMutationKind, MobileChatMutationRecord, MobileChatSenderResolutionRecord,
};

use super::super::chat_test_support::*;
use super::super::{MobilePeerUpsertRecord, MobileStoredChannelKind, MobileStoredChannelRecord};
use super::*;

const PEER: &str = "peer";
const CHANNEL: &str = "ch:beef";
const CHANNEL_ID: &str = "0F8E2D4C-1B3A-4C5D-9E8F-A1B2C3D4E5F6";
const DIGEST: &str = "digest-of-the-key";

/// Store `effects` as a session holding `digests` would.
fn store_batch(
    store: &MobileAppStore,
    digests: &HashMap<String, String>,
    silent_tests_in: Option<&str>,
    effects: &ChatBatchEffects,
) -> AppliedChatBatch {
    store
        .apply_chat_batch(
            &ChatBatchContext {
                owner_identity_id: OWNER,
                channel_digests: digests,
                silent_tests_in,
                now_ms: NOW,
            },
            effects,
        )
        .unwrap()
}

/// Store `effects` as a session holding no channel keys would.
fn batch(store: &MobileAppStore, effects: &ChatBatchEffects) -> MobileChatChangesRecord {
    store_batch(store, &HashMap::new(), None, effects).changes
}

fn mutations(mutations: Vec<MobileChatMutationRecord>) -> ChatBatchEffects {
    ChatBatchEffects {
        mutations,
        ..ChatBatchEffects::default()
    }
}

fn know(store: &MobileAppStore, address: &str) {
    store
        .upsert_peer(
            OWNER.into(),
            address.into(),
            MobilePeerUpsertRecord {
                is_saved: true,
                ..MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
}

fn join(store: &MobileAppStore, joined_phone: bool) {
    store
        .insert_channel(
            MobileStoredChannelRecord {
                id: CHANNEL_ID.into(),
                owner_identity_id: OWNER.into(),
                kind: MobileStoredChannelKind::Named,
                canonical_name: Some("ridge".into()),
                name: Some("Ridge".into()),
                alias: None,
                channel_id_hex: "beef".into(),
                tint: vec![0xBE, 0xEF, 0x01],
                region_code: None,
                max_flood_hops: None,
                joined_phone,
                joined_device: false,
                notifications_enabled: false,
                joined_at_ms: None,
            },
            DIGEST.into(),
            1,
        )
        .unwrap();
}

fn digests() -> HashMap<String, String> {
    HashMap::from([(CHANNEL.to_owned(), DIGEST.to_owned())])
}

fn notifying(mutation: MobileChatMutationRecord) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        notify: true,
        ..mutation
    }
}

fn last_heard(store: &MobileAppStore, address: &str) -> Option<i64> {
    scalar(
        store,
        &format!("SELECT last_heard_at_ms FROM node WHERE public_address = '{address}'"),
    )
}

#[test]
fn a_message_from_a_stored_peer_opens_their_conversation() {
    let (_directory, store) = open();
    know(&store, PEER);
    let changes = batch(&store, &mutations(vec![inbound(10, 1, PEER, 1, "hello")]));
    assert_eq!(changes.conversations, vec![PEER.to_owned()]);
    assert!(!changes.all_conversations);
    let conversations = store.list_direct_conversations(OWNER.into()).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].node.public_address, PEER);
}

#[test]
fn a_message_from_nobody_stored_is_kept_without_a_conversation() {
    let (_directory, store) = open();
    let changes = batch(&store, &mutations(vec![inbound(10, 1, PEER, 1, "hello")]));
    assert_eq!(changes.conversations, vec![PEER.to_owned()]);
    assert_eq!(transcript(&store, PEER).len(), 1);
    assert!(
        store
            .list_direct_conversations(OWNER.into())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_channel_message_opens_the_conversation_of_a_channel_the_phone_joined() {
    let (_directory, store) = open();
    join(&store, true);
    let effects = mutations(vec![inbound(10, 1, CHANNEL, 1, "to all")]);
    // The session holds no key under that address: no conversation.
    store_batch(&store, &HashMap::new(), None, &effects);
    assert!(
        store
            .list_channel_conversations(OWNER.into())
            .unwrap()
            .is_empty()
    );
    let changes = store_batch(&store, &digests(), None, &effects).changes;
    assert_eq!(changes.conversations, vec![CHANNEL.to_owned()]);
    let conversations = store.list_channel_conversations(OWNER.into()).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].conversation_address, CHANNEL);
    assert_eq!(conversations[0].channel_id, CHANNEL_ID);
}

#[test]
fn a_channel_only_the_radio_joined_gets_no_conversation() {
    let (_directory, store) = open();
    join(&store, false);
    store_batch(
        &store,
        &digests(),
        None,
        &mutations(vec![inbound(10, 1, CHANNEL, 1, "to all")]),
    );
    assert!(
        store
            .list_channel_conversations(OWNER.into())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn word_of_a_message_no_row_places_marks_every_conversation() {
    let (_directory, store) = open();
    batch(&store, &mutations(vec![outbound(10, 1, PEER, 1, "ours")]));
    // Of a stored message: its conversation alone.
    let placed = batch(
        &store,
        &ChatBatchEffects {
            deliveries: vec![delivery(10, 1, None, MobileChatDeliveryState::Sent)],
            ..ChatBatchEffects::default()
        },
    );
    assert_eq!(placed.conversations, vec![PEER.to_owned()]);
    assert!(!placed.all_conversations);
    // Of one this phone never stored.
    let unplaced = batch(
        &store,
        &ChatBatchEffects {
            deliveries: vec![delivery(10, 99, None, MobileChatDeliveryState::Sent)],
            ..ChatBatchEffects::default()
        },
    );
    assert!(unplaced.conversations.is_empty());
    assert!(unplaced.all_conversations);
}

#[test]
fn a_resolved_sender_marks_its_conversation() {
    let (_directory, store) = open();
    let changes = batch(
        &store,
        &ChatBatchEffects {
            sender_resolutions: vec![MobileChatSenderResolutionRecord {
                conversation_address: CHANNEL.into(),
                sender_hint: vec![1, 2, 3],
                sender_address: PEER.into(),
            }],
            ..ChatBatchEffects::default()
        },
    );
    assert_eq!(changes.conversations, vec![CHANNEL.to_owned()]);
}

#[test]
fn a_message_given_up_on_is_reported_once() {
    let (_directory, store) = open();
    batch(&store, &mutations(vec![outbound(10, 1, PEER, 1, "ours")]));
    let failed = ChatBatchEffects {
        deliveries: vec![delivery(10, 1, None, MobileChatDeliveryState::Failed)],
        ..ChatBatchEffects::default()
    };
    assert_eq!(
        batch(&store, &failed).delivery_failures,
        vec![MobileStoredChatDeliveryFailureRecord {
            conversation_address: PEER.into(),
            body: "ours".into(),
            undelivered: false,
        }]
    );
    // The same word again is no new failure.
    assert!(batch(&store, &failed).delivery_failures.is_empty());
}

#[test]
fn an_arrival_and_an_acknowledgment_both_count_as_hearing_the_peer() {
    let (_directory, store) = open();
    know(&store, PEER);
    know(&store, "other");
    store
        .set_notify_when_heard(OWNER.into(), PEER.into(), true)
        .unwrap();
    // One of ours going out is no word from them.
    let sent = batch(
        &store,
        &mutations(vec![outbound(10, 1, "other", 1, "ours")]),
    );
    assert!(sent.heard_watches.is_empty());
    assert_eq!(last_heard(&store, "other"), None);

    let heard = batch(
        &store,
        &ChatBatchEffects {
            mutations: vec![inbound(10, 2, PEER, 1, "theirs")],
            deliveries: vec![delivery(10, 1, None, MobileChatDeliveryState::Acknowledged)],
            ..ChatBatchEffects::default()
        },
    );
    // The watch was set off, and is set off once.
    assert_eq!(heard.heard_watches, vec![PEER.to_owned()]);
    assert!(last_heard(&store, PEER).is_some());
    assert!(last_heard(&store, "other").is_some());
    let again = batch(&store, &mutations(vec![inbound(10, 3, PEER, 2, "more")]));
    assert!(again.heard_watches.is_empty());
}

#[test]
fn a_channel_message_counts_as_hearing_its_sender_not_the_channel() {
    let (_directory, store) = open();
    know(&store, PEER);
    batch(
        &store,
        &mutations(vec![
            MobileChatMutationRecord {
                sender_address: Some(PEER.into()),
                ..inbound(10, 1, CHANNEL, 1, "to all")
            },
            // From a member whose hint has not resolved: nobody to mark.
            inbound(10, 2, CHANNEL, 2, "anonymous"),
        ]),
    );
    assert!(last_heard(&store, PEER).is_some());
}

#[test]
fn only_flagged_arrivals_and_materialized_edits_are_worth_telling() {
    let (_directory, store) = open();
    let reaction = MobileChatMutationRecord {
        message_type: Some(1),
        regarding_handle: Some(1),
        ..inbound(10, 4, PEER, 3, "<3")
    };
    // An edit whose original this phone never stored becomes a message of
    // its own; the engine could not flag it.
    let orphan_edit = MobileChatMutationRecord {
        original_handle: None,
        original_wire_id: Some(9),
        original_direction: Some(MobileChatDirection::Inbound),
        ..revision(MobileChatMutationKind::Edit, 10, 5, PEER, 0, Some("edited"))
    };
    let changes = batch(
        &store,
        &mutations(vec![
            outbound(10, 1, PEER, 1, "ours"),
            notifying(inbound(10, 2, PEER, 1, "told")),
            inbound(10, 3, PEER, 2, "not told"),
            notifying(reaction),
            orphan_edit,
        ]),
    );
    let told = changes
        .notifications
        .iter()
        .map(|notification| match notification {
            MobileChatNotificationRecord::Message { target } => ("message", target.body.clone()),
            MobileChatNotificationRecord::Reaction { target } => {
                assert_eq!(target.target_body, "ours");
                ("reaction", target.body.clone())
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        told,
        vec![
            ("message", "told".to_owned()),
            ("reaction", "<3".to_owned()),
            ("message", "edited".to_owned()),
        ]
    );
}

#[test]
fn test_messages_are_silent_only_in_the_conversation_the_batch_names() {
    let (_directory, store) = open();
    let silent = |address: &str| {
        scalar::<i64>(
            &store,
            &format!("SELECT silent FROM chat_message WHERE conversation_address = '{address}'"),
        )
    };
    let test = |address| mutations(vec![inbound(10, 1, address, 1, "TEST: radio check")]);
    store_batch(&store, &HashMap::new(), Some(CHANNEL), &test(CHANNEL));
    assert_eq!(silent(CHANNEL), 1);
    store_batch(
        &store,
        &HashMap::new(),
        Some(CHANNEL),
        &mutations(vec![inbound(10, 2, PEER, 1, "TEST: radio check")]),
    );
    assert_eq!(silent(PEER), 0);
}

#[test]
fn each_lookup_is_answered_with_what_the_archive_holds() {
    let (_directory, store) = open();
    store
        .commit_chat_compose_batch(
            OWNER.into(),
            MobileChatComposeBatchRecord {
                batch_id: 1,
                checkpoint: MobileChatCheckpointRecord {
                    conversation_address: PEER.into(),
                    next_id: 2,
                    epoch: 0,
                },
                archive_deletes: vec![],
                archives: vec![MobileChatArchiveRecord {
                    conversation_address: PEER.into(),
                    message_id: 1,
                    fragment_index: None,
                    payload: vec![1, 2, 3],
                }],
                mutations: vec![outbound(10, 1, PEER, 1, "ours")],
            },
            NOW,
        )
        .unwrap();
    let lookup = |request_id, message_id| MobileChatArchiveLookupRecord {
        request_id,
        conversation_address: PEER.into(),
        message_id,
        fragment_index: None,
    };
    let applied = store_batch(
        &store,
        &HashMap::new(),
        None,
        &ChatBatchEffects {
            archive_lookups: vec![lookup(7, 1), lookup(8, 2)],
            ..ChatBatchEffects::default()
        },
    );
    assert_eq!(
        applied.archive_answers,
        vec![(7, Some(vec![1, 2, 3])), (8, None)]
    );
    assert!(applied.changes.is_empty());
}

#[test]
fn a_batch_stored_twice_changes_nothing_more() {
    let (_directory, store) = open();
    know(&store, PEER);
    let effects = ChatBatchEffects {
        mutations: vec![
            outbound(10, 1, PEER, 1, "ours"),
            notifying(inbound(10, 2, PEER, 1, "theirs")),
        ],
        deliveries: vec![delivery(10, 1, None, MobileChatDeliveryState::Failed)],
        ..ChatBatchEffects::default()
    };
    let first = batch(&store, &effects);
    assert_eq!(first.delivery_failures.len(), 1);
    let rows = || scalar::<i64>(&store, "SELECT count(*) FROM chat_message");
    assert_eq!(rows(), 2);
    let second = batch(&store, &effects);
    assert_eq!(rows(), 2);
    assert!(second.delivery_failures.is_empty());
    assert_eq!(
        store.list_direct_conversations(OWNER.into()).unwrap().len(),
        1
    );
}

#[test]
fn a_batch_that_cannot_be_stored_leaves_nothing_behind() {
    let (_directory, store) = open();
    know(&store, PEER);
    // The second message is for an identity the store does not hold.
    let result = store.apply_chat_batch(
        &ChatBatchContext {
            owner_identity_id: "nobody",
            channel_digests: &HashMap::new(),
            silent_tests_in: None,
            now_ms: NOW,
        },
        &mutations(vec![inbound(10, 1, PEER, 1, "lost")]),
    );
    assert!(result.is_err());
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_applied_mutation"),
        0
    );
}
