use crate::mobile_chat::MobileChatPresence;

use super::super::chat_test_support::*;
use super::super::{MobileStoredChatQuoteRecord, MobileStoredChatReceptionRecord};
use super::*;

const ADDRESS: &str = "ch:staged";

fn staged(
    handle: u32,
    body: &str,
    outbound: bool,
    created_at_ms: i64,
) -> MobileStagedChatMessageRecord {
    MobileStagedChatMessageRecord {
        handle,
        body: body.into(),
        outbound,
        created_at_ms,
        sender_address: None,
        sender_hint: None,
        sender_handle: None,
        delivery_state: None,
        reception: None,
        reactions: vec![],
        regarding: None,
        is_deleted: false,
        wire_id: None,
        epoch: None,
    }
}

fn reaction(body: &str, outbound: bool, created_at_ms: i64) -> MobileStagedChatReactionRecord {
    MobileStagedChatReactionRecord {
        body: body.into(),
        outbound,
        created_at_ms,
        sender_address: None,
        sender_hint: None,
    }
}

#[test]
fn a_staged_transcript_reads_back_as_written() {
    let (_directory, store) = open();
    let reception = MobileStoredChatReceptionRecord {
        rssi_dbm: Some(-97),
        snr_centibels: Some(42),
        lqi: Some(180),
        hop_count: Some(2),
        route_hints: vec![vec![0x2A, 0xE1]],
        source_authenticated: true,
    };
    let messages = vec![
        MobileStagedChatMessageRecord {
            sender_address: Some("ann".into()),
            sender_hint: Some(vec![1, 2, 3]),
            sender_handle: Some("Ann".into()),
            reception: Some(reception.clone()),
            reactions: vec![
                reaction("<3", true, 1_500),
                MobileStagedChatReactionRecord {
                    sender_address: Some("bo".into()),
                    sender_hint: Some(vec![4, 5, 6]),
                    ..reaction("+1", false, 1_600)
                },
            ],
            ..staged(1, "Trail's open past the bridge.", false, 1_000)
        },
        MobileStagedChatMessageRecord {
            delivery_state: Some(MobileStoredChatDeliveryState::Acknowledged),
            regarding: Some(MobileStagedChatRegarding::Message { handle: 1 }),
            ..staged(2, "Thanks, heading up.", true, 2_000)
        },
        MobileStagedChatMessageRecord {
            regarding: Some(MobileStagedChatRegarding::Missing),
            ..staged(3, "About that earlier one.", false, 3_000)
        },
        MobileStagedChatMessageRecord {
            is_deleted: true,
            ..staged(4, "Never mind.", false, 4_000)
        },
    ];
    store
        .seed_staged_transcript(OWNER.into(), ADDRESS.into(), "77".into(), messages)
        .unwrap();
    let rows = transcript(&store, ADDRESS);
    let bodies: Vec<&str> = rows.iter().map(|message| message.body.as_str()).collect();
    assert_eq!(
        bodies,
        [
            "Trail's open past the bridge.",
            "Thanks, heading up.",
            "About that earlier one.",
            ""
        ]
    );
    let first = &rows[0];
    assert_eq!(
        (
            first.reference.session_id.as_str(),
            first.reference.handle,
            first.created_at_ms
        ),
        ("77", 1, 1_000)
    );
    assert_eq!(first.sender_address.as_deref(), Some("ann"));
    assert_eq!(first.sender_hint.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(first.sender_handle.as_deref(), Some("Ann"));
    assert_eq!(first.presence, MobileChatPresence::Present);
    // All of the reception, the route included.
    assert_eq!(first.reception.as_ref(), Some(&reception));
    let reactions: Vec<(&str, bool, Option<MobileStoredChatDeliveryState>, u32)> = first
        .reactions
        .iter()
        .map(|reaction| {
            (
                reaction.body.as_str(),
                reaction.outbound,
                reaction.delivery_state,
                reaction.reference.handle,
            )
        })
        .collect();
    assert_eq!(
        reactions,
        [
            (
                "<3",
                true,
                Some(MobileStoredChatDeliveryState::Acknowledged),
                STAGED_REACTION_HANDLE_BASE
            ),
            ("+1", false, None, STAGED_REACTION_HANDLE_BASE + 1)
        ]
    );

    let reply = &rows[1];
    assert!(reply.outbound);
    assert_eq!(
        reply.delivery_state,
        Some(MobileStoredChatDeliveryState::Acknowledged)
    );
    assert!(reply.is_reply);
    assert_eq!(
        reply
            .quote
            .as_ref()
            .and_then(|quote| quote.original.as_ref())
            .map(|original| original.body.as_str()),
        Some("Trail's open past the bridge.")
    );
    // A missing original is a reply quoting nothing.
    assert!(rows[2].is_reply);
    assert_eq!(
        rows[2].quote,
        Some(MobileStoredChatQuoteRecord { original: None })
    );
    // A tombstone says nothing.
    assert!(rows[3].is_deleted);

    // Seeding again replaces rather than duplicates.
    store
        .seed_staged_transcript(
            OWNER.into(),
            ADDRESS.into(),
            "77".into(),
            vec![staged(1, "Rewritten.", false, 1_000)],
        )
        .unwrap();
    assert_eq!(transcript(&store, ADDRESS)[0].body, "Rewritten.");
    assert_eq!(
        store.chat_message_count(OWNER.into(), ADDRESS.into()),
        Ok(4)
    );
}

#[test]
fn generated_messages_span_days_and_end_now() {
    let (_directory, store) = open();
    store
        .seed_generated_messages(OWNER.into(), ADDRESS.into(), 60, NOW)
        .unwrap();
    let rows = transcript(&store, ADDRESS);
    assert_eq!(rows.len(), 60);
    assert_eq!(rows.last().unwrap().created_at_ms, NOW);
    assert!(
        rows.iter()
            .all(|row| row.reference.session_id == format!("generated-{}", NOW % 1_000_000))
    );
    let handles: Vec<u32> = rows.iter().map(|row| row.reference.handle).collect();
    assert_eq!(handles, (0..60).collect::<Vec<_>>());
    assert!(
        rows.windows(2)
            .all(|pair| pair[0].created_at_ms <= pair[1].created_at_ms)
    );
    // Clusters share an instant; lulls run hours.
    assert!(
        rows.windows(2)
            .any(|pair| pair[0].created_at_ms == pair[1].created_at_ms)
    );
    assert!(
        rows.windows(2)
            .any(|pair| pair[1].created_at_ms - pair[0].created_at_ms == 5 * 3_600_000)
    );
    for row in &rows {
        let ours = row.reference.handle % 3 == 0;
        assert_eq!(row.outbound, ours);
        assert_eq!(
            row.delivery_state,
            ours.then_some(MobileStoredChatDeliveryState::Acknowledged)
        );
    }
    assert_eq!(rows[0].body, "Seeded message 1 of 60. Filler text. ");
    assert_eq!(
        rows[2].body,
        "Seeded message 3 of 60. Filler text. Filler text. Filler text. "
    );
    // Nothing to seed is nothing written.
    store
        .seed_generated_messages(OWNER.into(), "empty".into(), 0, NOW)
        .unwrap();
    assert_eq!(
        store.chat_message_count(OWNER.into(), "empty".into()),
        Ok(0)
    );
}

/// The stream checkpoints held, as `(conversation, next ID, epoch)`.
fn checkpoints(store: &MobileAppStore) -> Vec<(String, u8, u16)> {
    store
        .chat_checkpoints(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|checkpoint| {
            (
                checkpoint.conversation_address,
                checkpoint.next_id,
                checkpoint.epoch,
            )
        })
        .collect()
}

/// A message of ours under `wire_id` in epoch 0.
fn ours_on_the_wire(handle: u32, wire_id: u8, created_at_ms: i64) -> MobileStagedChatMessageRecord {
    MobileStagedChatMessageRecord {
        wire_id: Some(wire_id),
        epoch: Some(0),
        reactions: vec![reaction("<3", false, created_at_ms + 1)],
        ..staged(handle, "Ours", true, created_at_ms)
    }
}

#[test]
fn staged_wire_fields_are_written_as_given_and_reactions_carry_none() {
    let (_directory, store) = open();
    let messages = vec![
        MobileStagedChatMessageRecord {
            wire_id: Some(254),
            ..staged(1, "Theirs", false, 1_000)
        },
        ours_on_the_wire(2, 255, 2_000),
    ];
    store
        .seed_staged_transcript(OWNER.into(), ADDRESS.into(), "staged".into(), messages)
        .unwrap();
    let rows = transcript(&store, ADDRESS);
    let wire: Vec<_> = rows.iter().map(|row| (row.wire_id, row.epoch)).collect();
    assert_eq!(wire, [(Some(254), None), (Some(255), Some(0))]);
    let reaction = &rows[1].reactions[0];
    assert_eq!((reaction.wire_id, reaction.epoch), (None, None));
}

#[test]
fn ours_on_the_wire_set_the_stream_to_continue_after_the_newest() {
    let (_directory, store) = open();
    store
        .seed_staged_transcript(
            OWNER.into(),
            ADDRESS.into(),
            "staged".into(),
            vec![
                ours_on_the_wire(1, 254, 1_000),
                // Newest by time, whatever its handle.
                ours_on_the_wire(3, 255, 3_000),
                ours_on_the_wire(2, 253, 2_000),
            ],
        )
        .unwrap();
    assert_eq!(checkpoints(&store), [(ADDRESS.to_owned(), 0, 0)], "wrapped");
}

#[test]
fn a_reseed_never_rewinds_a_stream_already_moved_on() {
    let (_directory, store) = open();
    let seed = || {
        store
            .seed_staged_transcript(
                OWNER.into(),
                ADDRESS.into(),
                "staged".into(),
                vec![ours_on_the_wire(1, 255, 1_000)],
            )
            .unwrap();
    };
    seed();
    // Real sends moved the stream on.
    store
        .connection()
        .execute(
            "UPDATE chat_stream_checkpoint SET next_id = 7 WHERE conversation_address = ?",
            [ADDRESS],
        )
        .unwrap();
    seed();
    assert_eq!(checkpoints(&store), [(ADDRESS.to_owned(), 7, 0)]);
}

#[test]
fn a_staged_transcript_with_nothing_of_ours_on_the_wire_sets_no_stream() {
    let (_directory, store) = open();
    store
        .seed_staged_transcript(
            OWNER.into(),
            ADDRESS.into(),
            "staged".into(),
            vec![
                staged(1, "Ours, unnamed", true, 1_000),
                MobileStagedChatMessageRecord {
                    wire_id: Some(255),
                    ..staged(2, "Theirs", false, 2_000)
                },
            ],
        )
        .unwrap();
    assert!(checkpoints(&store).is_empty());
}
