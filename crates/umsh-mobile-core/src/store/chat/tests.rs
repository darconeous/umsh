use crate::RouterHintRecord;
use crate::mobile_chat::MobileChatRxMetadataRecord;

use super::super::MobileStoredChatReceptionRecord;
use super::super::chat_test_support::*;
use super::*;

const PEER: &str = "peer";

fn hint(bytes: &[u8]) -> RouterHintRecord {
    RouterHintRecord {
        bytes: bytes.to_vec(),
        text: String::new(),
    }
}

fn deliver(
    store: &MobileAppStore,
    deliveries: Vec<MobileChatDeliveryRecord>,
) -> Vec<MobileStoredChatDeliveryFailureRecord> {
    store
        .apply_chat_deliveries(OWNER.into(), deliveries, NOW)
        .unwrap()
}

fn rx(route_hints: Vec<Vec<u8>>) -> MobileChatRxMetadataRecord {
    MobileChatRxMetadataRecord {
        rssi_dbm: Some(-90),
        snr_centibels: Some(35),
        lqi: None,
        hop_count: Some(2),
        route_hints,
        source_authenticated: true,
        buffered_age_seconds: 0,
    }
}

// The persistence smoke test's chat checks.

/// `checkRepeats`: the repeaters heard carrying a message fold across its
/// fragments and across each fragment's transmissions.
#[test]
fn the_smoke_test_s_repeat_checks() {
    let (_directory, store) = open();
    let peer = "repeat-peer";
    apply(
        &store,
        vec![MobileChatMutationRecord {
            present_fragments: Some(2),
            fragment_count: Some(2),
            ..outbound(300, 1, peer, 1, "Anyone on the ridge?")
        }],
    );
    let stored = || transcript(&store, peer).remove(0);
    assert_eq!(stored().repeats, None, "nothing sent, so no repeats yet");

    deliver(
        &store,
        vec![delivery(300, 1, Some(0), MobileChatDeliveryState::Sent)],
    );
    let sent = stored();
    assert_eq!(
        sent.delivery_state,
        Some(MobileStoredChatDeliveryState::Sent)
    );
    let repeats = sent.repeats.unwrap();
    assert_eq!(
        (
            repeats.repeaters.len(),
            repeats.anonymous,
            repeats.progress_at_ms
        ),
        (0, 0, NOW),
        "sending stamps the message's progress"
    );

    let ridge = hint(&[0x01, 0x02]);
    let butte = hint(&[0x03, 0x04]);
    let peak = hint(&[0x05, 0x06]);
    store
        .apply_chat_repeats(
            OWNER.into(),
            vec![
                MobileChatRepeatRecord {
                    session_id: 300,
                    handle: 1,
                    fragment_index: Some(0),
                    repeaters: vec![ridge.clone()],
                    anonymous_repeats: 1,
                },
                MobileChatRepeatRecord {
                    session_id: 300,
                    handle: 1,
                    fragment_index: Some(1),
                    repeaters: vec![ridge, butte],
                    anonymous_repeats: 0,
                },
                // A resend of the first fragment tallies afresh.
                MobileChatRepeatRecord {
                    session_id: 300,
                    handle: 1,
                    fragment_index: Some(0),
                    repeaters: vec![peak],
                    anonymous_repeats: 0,
                },
            ],
            NOW + 5,
        )
        .unwrap();
    let repeats = stored().repeats.unwrap();
    assert_eq!(repeats.repeaters[0], [0x01, 0x02]);
    let mut named = repeats.repeaters.clone();
    named.sort();
    assert_eq!(named, [[0x01, 0x02], [0x03, 0x04], [0x05, 0x06]]);
    assert_eq!(repeats.anonymous, 1);
    assert_eq!(repeats.repeaters.len() as i64 + repeats.anonymous, 4);
    assert_eq!(repeats.progress_at_ms, NOW + 5);
}

/// The upgrade check's chat half: a store's checkpoints and archived
/// payloads read back as written.
#[test]
fn the_smoke_test_s_upgrade_checkpoint_and_archive_read_back() {
    let (_directory, store) = open();
    store
        .connection()
        .execute_batch(
            "INSERT INTO chat_stream_checkpoint (owner_identity_id, conversation_address,
                next_id, epoch, updated_at_ms)
            VALUES ('alice', 'historical-peer', 7, 2, 3000);
            INSERT INTO chat_outbound_archive (owner_identity_id, conversation_address,
                message_id, fragment_index, payload)
            VALUES ('alice', 'historical-peer', 6, 0, X'010203');",
        )
        .unwrap();
    assert_eq!(
        store.chat_checkpoints(OWNER.into()).unwrap(),
        vec![MobileChatCheckpointRecord {
            conversation_address: "historical-peer".into(),
            next_id: 7,
            epoch: 2,
        }]
    );
    let lookup = |fragment_index| MobileChatArchiveLookupRecord {
        request_id: 0,
        conversation_address: "historical-peer".into(),
        message_id: 6,
        fragment_index,
    };
    assert_eq!(
        store.chat_archive(OWNER.into(), lookup(Some(0))),
        Ok(Some(vec![1, 2, 3]))
    );
    // The unfragmented entry is a different key.
    assert_eq!(store.chat_archive(OWNER.into(), lookup(None)), Ok(None));
    assert_eq!(store.chat_archive("bob".into(), lookup(Some(0))), Ok(None));
}

// Compose batches.

fn compose(
    address: &str,
    next_id: u8,
    archives: Vec<MobileChatArchiveRecord>,
    archive_deletes: Vec<MobileChatArchiveDeleteRecord>,
    mutations: Vec<MobileChatMutationRecord>,
) -> MobileChatComposeBatchRecord {
    MobileChatComposeBatchRecord {
        batch_id: 1,
        checkpoint: MobileChatCheckpointRecord {
            conversation_address: address.into(),
            next_id,
            epoch: 3,
        },
        archive_deletes,
        archives,
        mutations,
    }
}

fn archive(message_id: u8, fragment_index: Option<u8>, payload: &[u8]) -> MobileChatArchiveRecord {
    MobileChatArchiveRecord {
        conversation_address: PEER.into(),
        message_id,
        fragment_index,
        payload: payload.to_vec(),
    }
}

fn archived(store: &MobileAppStore, message_id: u8) -> Vec<(i64, Vec<u8>)> {
    store
        .connection()
        .prepare(
            "SELECT fragment_index, payload FROM chat_outbound_archive
            WHERE message_id = ? ORDER BY fragment_index",
        )
        .unwrap()
        .query_map(params![message_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn a_compose_commits_its_checkpoint_archive_and_rows_together() {
    let (_directory, store) = open();
    store
        .commit_chat_compose_batch(
            OWNER.into(),
            compose(
                PEER,
                5,
                vec![archive(4, Some(0), &[1]), archive(4, Some(1), &[2])],
                vec![],
                vec![outbound(10, 1, PEER, 4, "hello")],
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(
        store.chat_checkpoints(OWNER.into()).unwrap()[0],
        MobileChatCheckpointRecord {
            conversation_address: PEER.into(),
            next_id: 5,
            epoch: 3,
        }
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT updated_at_ms FROM chat_stream_checkpoint"),
        NOW
    );
    assert_eq!(archived(&store, 4), [(0, vec![1]), (1, vec![2])]);
    let hello = message(&store, PEER, "hello");
    assert!(hello.outbound);
    assert_eq!(
        hello.delivery_state,
        Some(MobileStoredChatDeliveryState::Pending)
    );
    assert_eq!(hello.created_at_ms, NOW);

    // An edit retires the superseded fragments before its own land: the
    // second fragment of the old content must not survive.
    store
        .commit_chat_compose_batch(
            OWNER.into(),
            compose(
                PEER,
                6,
                vec![archive(4, Some(0), &[9])],
                vec![MobileChatArchiveDeleteRecord {
                    conversation_address: PEER.into(),
                    message_id: 4,
                }],
                vec![revision(
                    MobileChatMutationKind::Edit,
                    10,
                    2,
                    PEER,
                    1,
                    Some("hello there"),
                )],
            ),
            NOW + 1,
        )
        .unwrap();
    assert_eq!(archived(&store, 4), [(0, vec![9])]);
    assert_eq!(store.chat_checkpoints(OWNER.into()).unwrap()[0].next_id, 6);
    assert_eq!(
        scalar::<i64>(&store, "SELECT updated_at_ms FROM chat_stream_checkpoint"),
        NOW + 1
    );
}

#[test]
fn a_compose_that_fails_part_way_writes_nothing() {
    let (_directory, store) = open();
    store
        .connection()
        .execute_batch(
            "CREATE TRIGGER refuse BEFORE INSERT ON chat_message
            BEGIN SELECT RAISE(FAIL, 'test'); END;",
        )
        .unwrap();
    assert!(matches!(
        store.commit_chat_compose_batch(
            OWNER.into(),
            compose(
                PEER,
                5,
                vec![archive(4, None, &[1])],
                vec![],
                vec![outbound(10, 1, PEER, 4, "hello")],
            ),
            NOW,
        ),
        Err(MobileStoreError::Failed { .. })
    ));
    for table in [
        "chat_stream_checkpoint",
        "chat_outbound_archive",
        "chat_applied_mutation",
    ] {
        assert_eq!(
            scalar::<i64>(&store, &format!("SELECT count(*) FROM {table}")),
            0,
            "{table}"
        );
    }
}

#[test]
fn a_failed_compose_marks_its_outbound_rows_and_edited_rows_undelivered() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![
            outbound(10, 1, PEER, 1, "first"),
            outbound(10, 2, PEER, 2, "second"),
            inbound(10, 3, PEER, 1, "theirs"),
        ],
    );
    deliver(
        &store,
        vec![delivery(10, 2, None, MobileChatDeliveryState::Acknowledged)],
    );
    // A compose of a new message and an edit of the delivered one, neither
    // released.
    let batch = compose(
        PEER,
        5,
        vec![],
        vec![],
        vec![
            outbound(10, 4, PEER, 3, "third"),
            revision(
                MobileChatMutationKind::Edit,
                10,
                5,
                PEER,
                2,
                Some("second!"),
            ),
            inbound(10, 6, PEER, 2, "theirs again"),
        ],
    );
    store
        .commit_chat_compose_batch(OWNER.into(), batch.clone(), NOW)
        .unwrap();
    store
        .mark_chat_compose_batch_failed(OWNER.into(), batch)
        .unwrap();
    let state = |body| message(&store, PEER, body).delivery_state;
    assert_eq!(
        state("third"),
        Some(MobileStoredChatDeliveryState::Undelivered)
    );
    assert_eq!(
        state("second!"),
        Some(MobileStoredChatDeliveryState::Undelivered)
    );
    // Not in the batch, or not ours.
    assert_eq!(state("first"), Some(MobileStoredChatDeliveryState::Pending));
    assert_eq!(state("theirs again"), None);
}

// Mutations.

#[test]
fn a_mutation_applies_once_per_revision() {
    let (_directory, store) = open();
    apply(&store, vec![inbound(10, 1, PEER, 1, "first")]);
    // Anything a replay rewrote would show here.
    store
        .connection()
        .execute("UPDATE chat_message SET body = 'marked'", [])
        .unwrap();
    apply(&store, vec![inbound(10, 1, PEER, 1, "first")]);
    assert_eq!(transcript(&store, PEER)[0].body, "marked");
    // So does an older revision arriving late.
    apply(
        &store,
        vec![MobileChatMutationRecord {
            revision: 2,
            ..inbound(10, 1, PEER, 1, "third")
        }],
    );
    apply(
        &store,
        vec![MobileChatMutationRecord {
            revision: 1,
            ..inbound(10, 1, PEER, 1, "second")
        }],
    );
    assert_eq!(transcript(&store, PEER)[0].body, "third");
    assert_eq!(
        scalar::<i64>(&store, "SELECT revision FROM chat_applied_mutation"),
        2
    );

    // The ledger is the identity's own: another identity's first revision
    // of the same handle applies.
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store
        .apply_chat_mutations(
            "bob".into(),
            vec![inbound(10, 1, PEER, 1, "bob's")],
            NOW,
            None,
        )
        .unwrap();
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        2
    );
    assert_eq!(transcript(&store, PEER)[0].body, "third");
}

#[test]
fn an_insert_writes_the_row_as_the_engine_described_it() {
    let (_directory, store) = open();
    let address = "ch:beef";
    apply(
        &store,
        vec![MobileChatMutationRecord {
            sender_address: Some("member".into()),
            sender_hint: Some(vec![1, 2, 3]),
            sender_handle: Some("Ridge".into()),
            message_type: Some(1),
            epoch: Some(4),
            client_token: Some(77),
            background_color: Some(vec![]),
            text_color: Some(vec![0xFF, 0, 0]),
            rx: Some(MobileChatRxMetadataRecord {
                lqi: Some(200),
                buffered_age_seconds: 30,
                ..rx(vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]])
            }),
            ..inbound(10, 1, address, 9, "is at the trailhead")
        }],
    );
    let row = transcript(&store, address).remove(0);
    assert_eq!(row.reference.session_id, "10");
    assert_eq!(row.reference.handle, 1);
    assert_eq!((row.wire_id, row.epoch), (Some(9), Some(4)));
    assert!(row.is_status);
    assert!(!row.outbound);
    assert_eq!(row.delivery_state, None);
    // Stamped when it was heard off the air, not when the drain landed it.
    assert_eq!(row.created_at_ms, NOW - 30_000);
    assert_eq!(row.sender_address.as_deref(), Some("member"));
    assert_eq!(row.sender_hint.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(row.sender_handle.as_deref(), Some("Ridge"));
    let reception = row.reception.unwrap();
    assert_eq!(
        reception,
        MobileStoredChatReceptionRecord {
            rssi_dbm: Some(-90),
            snr_centibels: Some(35),
            lqi: Some(200),
            hop_count: Some(2),
            route_hints: vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]],
            source_authenticated: true,
        }
    );
    // The route is one packed blob; an empty color is NULL, as the Swift
    // store bound it.
    let column = |name: &str| -> rusqlite::types::Value {
        scalar(&store, &format!("SELECT {name} FROM chat_message"))
    };
    use rusqlite::types::Value;
    assert_eq!(
        column("rx_route_hints"),
        Value::Blob(vec![0xAA, 0xBB, 0xCC, 0xDD])
    );
    assert_eq!(column("background_color"), Value::Null);
    assert_eq!(column("text_color"), Value::Blob(vec![0xFF, 0, 0]));
    assert_eq!(column("client_token"), Value::Integer(77));
    // A fresh row reports its own transmission.
    assert_eq!(column("delivery_session_id"), Value::Text("10".into()));
    assert_eq!(column("delivery_handle"), Value::Integer(1));

    // A frame with no route hints stores none, as NULL.
    apply(
        &store,
        vec![MobileChatMutationRecord {
            rx: Some(rx(vec![])),
            ..inbound(10, 2, PEER, 1, "direct")
        }],
    );
    assert_eq!(
        scalar::<Option<Vec<u8>>>(
            &store,
            "SELECT rx_route_hints FROM chat_message WHERE handle = 2"
        ),
        None
    );
    assert_eq!(
        message(&store, PEER, "direct")
            .reception
            .unwrap()
            .route_hints,
        Vec::<Vec<u8>>::new()
    );
}

#[test]
fn a_record_missing_its_address_direction_or_body_is_dropped_but_ledgered() {
    let (_directory, store) = open();
    let missing = [
        MobileChatMutationRecord {
            conversation_address: None,
            ..inbound(10, 1, PEER, 1, "a")
        },
        MobileChatMutationRecord {
            direction: None,
            ..inbound(10, 2, PEER, 2, "b")
        },
        MobileChatMutationRecord {
            body: None,
            ..inbound(10, 3, PEER, 3, "c")
        },
    ];
    apply(&store, missing.to_vec());
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        0
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_applied_mutation"),
        3
    );
}

#[test]
fn a_gap_placeholder_fills_in_and_keeps_what_it_had() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![MobileChatMutationRecord {
            presence: MobileChatPresence::GapPending,
            rx: Some(rx(vec![vec![1, 2]])),
            ..inbound(10, 1, PEER, 4, "")
        }],
    );
    assert_eq!(
        transcript(&store, PEER)[0].presence,
        MobileChatPresence::GapPending
    );
    apply(
        &store,
        vec![MobileChatMutationRecord {
            revision: 1,
            received_late: true,
            ..inbound(10, 1, PEER, 4, "filled in")
        }],
    );
    let row = transcript(&store, PEER).remove(0);
    assert_eq!(row.presence, MobileChatPresence::Present);
    assert!(row.received_late);
    // The placeholder's reception survives a fill that carries none.
    assert_eq!(row.reception.unwrap().route_hints, [[1, 2]]);
    assert_eq!(row.created_at_ms, NOW);

    // A late flag is never cleared.
    apply(
        &store,
        vec![MobileChatMutationRecord {
            revision: 2,
            ..inbound(10, 1, PEER, 4, "filled in again")
        }],
    );
    assert!(transcript(&store, PEER)[0].received_late);
}

#[test]
fn an_update_body_completes_a_message_without_touching_presence() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![MobileChatMutationRecord {
            complete: Some(false),
            present_fragments: Some(1),
            fragment_count: Some(2),
            ..inbound(10, 1, PEER, 4, "half")
        }],
    );
    apply(
        &store,
        vec![MobileChatMutationRecord {
            kind: MobileChatMutationKind::UpdateBody,
            revision: 1,
            conversation_address: None,
            direction: None,
            received_late: true,
            rx: Some(rx(vec![vec![5, 6]])),
            presence: MobileChatPresence::GapIdle,
            present_fragments: Some(2),
            ..inbound(10, 1, PEER, 4, "half and the rest")
        }],
    );
    let row = transcript(&store, PEER).remove(0);
    assert_eq!(row.body, "half and the rest");
    assert_eq!(row.presence, MobileChatPresence::Present);
    assert!(row.received_late);
    assert_eq!(row.reception.unwrap().route_hints, [[5, 6]]);
    assert_eq!(
        scalar::<i64>(&store, "SELECT complete FROM chat_message"),
        1
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT present_fragments FROM chat_message"),
        2
    );
    // An update of nothing stored is not an error.
    apply(
        &store,
        vec![MobileChatMutationRecord {
            kind: MobileChatMutationKind::UpdateBody,
            ..inbound(10, 9, PEER, 4, "nobody")
        }],
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        1
    );
}

#[test]
fn test_messages_in_the_named_conversation_arrive_silently() {
    let (_directory, store) = open();
    let emergency = "ch:emergency";
    store
        .apply_chat_mutations(
            OWNER.into(),
            vec![
                inbound(10, 1, emergency, 1, "TEST: radio check"),
                inbound(10, 2, emergency, 2, "real trouble"),
                inbound(10, 3, "ch:other", 1, "TEST: radio check"),
                outbound(10, 4, emergency, 1, "test: mine"),
            ],
            NOW,
            Some(emergency.into()),
        )
        .unwrap();
    let silent = |handle: u32| -> i64 {
        scalar(
            &store,
            &format!("SELECT silent FROM chat_message WHERE handle = {handle}"),
        )
    };
    assert_eq!([silent(1), silent(2), silent(3), silent(4)], [1, 0, 0, 0]);
    // Without the switch, nothing is silent.
    apply(&store, vec![inbound(10, 5, emergency, 3, "TEST: again")]);
    assert_eq!(silent(5), 0);

    // A fragmented message completing as a test is silent from then on.
    store
        .apply_chat_mutations(
            OWNER.into(),
            vec![
                inbound(10, 6, emergency, 4, "TE"),
                MobileChatMutationRecord {
                    kind: MobileChatMutationKind::UpdateBody,
                    revision: 1,
                    ..inbound(10, 6, emergency, 4, "TEST: in parts")
                },
            ],
            NOW,
            Some(emergency.into()),
        )
        .unwrap();
    assert_eq!(silent(6), 1);
    // And a completion outside the named conversation is not.
    store
        .apply_chat_mutations(
            OWNER.into(),
            vec![MobileChatMutationRecord {
                kind: MobileChatMutationKind::UpdateBody,
                revision: 1,
                ..inbound(10, 3, "ch:other", 1, "TEST: radio check, done")
            }],
            NOW,
            Some(emergency.into()),
        )
        .unwrap();
    assert_eq!(silent(3), 0);
    // A silent row is still a transcript row.
    assert_eq!(
        store
            .chat_message_count(OWNER.into(), emergency.into())
            .unwrap(),
        5
    );
}

// Edits and deletes.

#[test]
fn an_edit_of_ours_keeps_the_first_text_and_says_it_was_edited() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "draft")]);
    apply(
        &store,
        vec![
            MobileChatMutationRecord {
                forward_secret: Some(true),
                ..revision(MobileChatMutationKind::Edit, 10, 2, PEER, 1, Some("second"))
            },
            revision(MobileChatMutationKind::Edit, 10, 3, PEER, 1, Some("third")),
        ],
    );
    let row = transcript(&store, PEER).remove(0);
    assert_eq!(row.body, "third");
    assert_eq!(row.original_body.as_deref(), Some("draft"));
    assert!(row.is_edited);
    // The edit that said so set it, and the one that did not left it.
    assert!(row.is_forward_secret);
    // Still keyed by its compose.
    assert_eq!(
        (row.reference.session_id.as_str(), row.reference.handle),
        ("10", 1)
    );
}

#[test]
fn an_edit_that_changes_nothing_is_not_an_edit() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "same")]);
    apply(
        &store,
        vec![revision(
            MobileChatMutationKind::Edit,
            10,
            2,
            PEER,
            1,
            Some("same"),
        )],
    );
    let row = transcript(&store, PEER).remove(0);
    assert!(!row.is_edited);
    assert_eq!(row.original_body, None);
}

#[test]
fn an_inbound_edit_is_marked_but_keeps_no_original() {
    let (_directory, store) = open();
    apply(&store, vec![inbound(10, 1, PEER, 1, "theirs")]);
    apply(
        &store,
        vec![MobileChatMutationRecord {
            direction: Some(MobileChatDirection::Inbound),
            ..revision(
                MobileChatMutationKind::Edit,
                10,
                2,
                PEER,
                1,
                Some("theirs, fixed"),
            )
        }],
    );
    let row = transcript(&store, PEER).remove(0);
    assert_eq!(row.body, "theirs, fixed");
    assert!(row.is_edited);
    assert_eq!(row.original_body, None);
    assert_eq!(row.delivery_state, None);
}

#[test]
fn an_edit_or_delete_finds_its_original_by_wire_reference() {
    let (_directory, store) = open();
    // Two generations of wire ID 3 on our stream: the newer is the one a
    // reference means.
    apply(
        &store,
        vec![
            MobileChatMutationRecord {
                epoch: Some(1),
                ..outbound(10, 1, PEER, 3, "old three")
            },
            MobileChatMutationRecord {
                epoch: Some(2),
                ..outbound(10, 2, PEER, 3, "new three")
            },
            inbound(10, 3, PEER, 3, "their three"),
        ],
    );
    let by_wire = |kind, handle, body: Option<&str>, direction| MobileChatMutationRecord {
        original_handle: None,
        original_wire_id: Some(3),
        original_direction: Some(direction),
        ..revision(kind, 20, handle, PEER, 0, body)
    };
    apply(
        &store,
        vec![by_wire(
            MobileChatMutationKind::Edit,
            1,
            Some("new three, edited"),
            MobileChatDirection::Outbound,
        )],
    );
    let bodies: Vec<String> = transcript(&store, PEER)
        .into_iter()
        .map(|message| message.body)
        .collect();
    assert_eq!(bodies, ["old three", "new three, edited", "their three"]);

    apply(
        &store,
        vec![by_wire(
            MobileChatMutationKind::Delete,
            2,
            None,
            MobileChatDirection::Inbound,
        )],
    );
    // A tombstone: the row stays, emptied and marked.
    let tombstone = transcript(&store, PEER).remove(2);
    assert!(tombstone.is_deleted);
    assert_eq!(tombstone.body, "");
    assert_eq!(
        (
            tombstone.reference.session_id.as_str(),
            tombstone.reference.handle
        ),
        ("10", 3)
    );
    assert_eq!(store.chat_message_count(OWNER.into(), PEER.into()), Ok(3));
}

#[test]
fn a_delete_leaves_a_tombstone_that_notifies_nobody() {
    let (_directory, store) = open();
    apply(&store, vec![inbound(10, 1, PEER, 1, "regret")]);
    assert!(
        store
            .chat_notification_target(OWNER.into(), 10, 1)
            .unwrap()
            .is_some()
    );
    apply(
        &store,
        vec![revision(
            MobileChatMutationKind::Delete,
            10,
            2,
            PEER,
            1,
            Some("ignored"),
        )],
    );
    let row = transcript(&store, PEER).remove(0);
    assert!(row.is_deleted);
    assert_eq!(row.body, "");
    assert!(!row.is_edited);
    assert_eq!(
        store.chat_notification_target(OWNER.into(), 10, 1),
        Ok(None)
    );
    // A delete of nothing stored is nothing.
    apply(
        &store,
        vec![revision(
            MobileChatMutationKind::Delete,
            10,
            3,
            PEER,
            99,
            None,
        )],
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        1
    );
}

fn orphan_edit(handle: u32, wire_id: u8, body: &str) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        original_handle: None,
        original_wire_id: Some(wire_id),
        original_direction: Some(MobileChatDirection::Inbound),
        original_sender_hint: Some(vec![7, 7, 7]),
        ..revision(
            MobileChatMutationKind::Edit,
            20,
            handle,
            PEER,
            0,
            Some(body),
        )
    }
}

#[test]
fn an_edit_of_a_message_never_stored_arrives_as_that_message() {
    let (_directory, store) = open();
    // A reaction waiting on the original, from the same member.
    apply(
        &store,
        vec![MobileChatMutationRecord {
            message_type: Some(1),
            regarding_wire_id: Some(5),
            regarding_direction: Some(MobileChatDirection::Inbound),
            regarding_sender_hint: Some(vec![7, 7, 7]),
            ..inbound(20, 1, PEER, 6, "<3")
        }],
    );
    let edit = orphan_edit(2, 5, "the whole message");
    assert_eq!(apply(&store, vec![edit.clone()]), vec![edit.clone()]);
    let row = message(&store, PEER, "the whole message");
    assert!(!row.outbound);
    assert!(row.received_late);
    assert!(row.is_edit_of_unknown);
    assert!(!row.is_edited);
    // Keyed by the edit, carrying the original's wire ID and sender.
    assert_eq!(
        (row.reference.session_id.as_str(), row.reference.handle),
        ("20", 2)
    );
    assert_eq!(row.wire_id, Some(5));
    assert_eq!(row.sender_hint.as_deref(), Some(&[7u8, 7, 7][..]));
    assert_eq!(row.created_at_ms, NOW);
    // The waiting reaction is adopted.
    assert_eq!(row.reactions.len(), 1);
    assert_eq!(row.reactions[0].body, "<3");

    // Applied again, it is nothing new.
    assert_eq!(apply(&store, vec![edit]), vec![]);
    // A later edit naming the same wire ID revises it.
    apply(
        &store,
        vec![MobileChatMutationRecord {
            original_sender_hint: None,
            ..orphan_edit(3, 5, "the whole message, again")
        }],
    );
    assert_eq!(
        transcript(&store, PEER)
            .into_iter()
            .filter(|message| message.body.starts_with("the whole"))
            .count(),
        1
    );
}

#[test]
fn only_an_inbound_edit_with_words_materializes() {
    let (_directory, store) = open();
    let dropped = [
        // Of one of ours.
        MobileChatMutationRecord {
            original_direction: Some(MobileChatDirection::Outbound),
            ..orphan_edit(1, 5, "ours")
        },
        // Empty.
        orphan_edit(2, 6, ""),
        // With no wire reference.
        MobileChatMutationRecord {
            original_wire_id: None,
            ..orphan_edit(3, 7, "nowhere")
        },
        // A delete.
        MobileChatMutationRecord {
            kind: MobileChatMutationKind::Delete,
            ..orphan_edit(4, 8, "gone")
        },
    ];
    assert_eq!(apply(&store, dropped.to_vec()), vec![]);
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        0
    );
}

// Replies and reactions arriving before what they are about.

#[test]
fn a_reaction_that_outruns_its_message_is_adopted_when_it_lands() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![MobileChatMutationRecord {
            message_type: Some(1),
            regarding_wire_id: Some(4),
            regarding_direction: Some(MobileChatDirection::Inbound),
            ..inbound(10, 1, PEER, 1, "+1")
        }],
    );
    assert_eq!(
        scalar::<Option<String>>(
            &store,
            "SELECT regarding_target_session_id FROM chat_message"
        ),
        None
    );
    // Reactions are not transcript rows.
    assert_eq!(transcript(&store, PEER), vec![]);
    // Another conversation's wire ID 4 is not it.
    apply(&store, vec![inbound(11, 1, "other", 4, "elsewhere")]);
    assert_eq!(
        scalar::<Option<String>>(
            &store,
            "SELECT regarding_target_session_id FROM chat_message WHERE is_reaction = 1"
        ),
        None
    );
    apply(&store, vec![inbound(12, 1, PEER, 4, "the message")]);
    let row = message(&store, PEER, "the message");
    assert_eq!(row.reactions.len(), 1);
    assert_eq!(
        (
            row.reactions[0].reference.session_id.as_str(),
            row.reactions[0].reference.handle
        ),
        ("10", 1)
    );
}

#[test]
fn a_reference_to_our_stream_that_matches_nothing_there_means_theirs() {
    let (_directory, store) = open();
    apply(&store, vec![inbound(10, 1, PEER, 4, "theirs")]);
    apply(
        &store,
        vec![MobileChatMutationRecord {
            regarding_wire_id: Some(4),
            regarding_direction: Some(MobileChatDirection::Outbound),
            ..inbound(11, 1, PEER, 5, "a reply")
        }],
    );
    let reply = message(&store, PEER, "a reply");
    assert_eq!(
        reply.reply_target,
        Some(MobileStoredChatMessageRefRecord {
            session_id: "10".into(),
            handle: 1,
        })
    );
    // When ours has it, ours it is.
    apply(&store, vec![outbound(12, 1, PEER, 4, "ours")]);
    apply(
        &store,
        vec![MobileChatMutationRecord {
            regarding_wire_id: Some(4),
            regarding_direction: Some(MobileChatDirection::Outbound),
            ..inbound(12, 2, PEER, 6, "to ours")
        }],
    );
    assert_eq!(
        message(&store, PEER, "to ours")
            .reply_target
            .unwrap()
            .session_id,
        "12"
    );
}

#[test]
fn a_group_reference_matches_its_member_s_stream_only() {
    let (_directory, store) = open();
    let group = "ch:beef";
    let member = |session, handle, hint: u8, wire_id, body: &str| MobileChatMutationRecord {
        sender_hint: Some(vec![hint; 3]),
        ..inbound(session, handle, group, wire_id, body)
    };
    apply(
        &store,
        vec![
            member(10, 1, 1, 4, "from one"),
            member(10, 2, 2, 4, "from two"),
        ],
    );
    apply(
        &store,
        vec![MobileChatMutationRecord {
            regarding_wire_id: Some(4),
            regarding_direction: Some(MobileChatDirection::Inbound),
            regarding_sender_hint: Some(vec![1; 3]),
            ..member(11, 1, 3, 9, "to one")
        }],
    );
    assert_eq!(
        message(&store, group, "to one")
            .reply_target
            .unwrap()
            .handle,
        1
    );
}

// Delivery.

#[test]
fn delivery_resolves_from_every_fragment_and_reports_each_failure_once() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![MobileChatMutationRecord {
            fragment_count: Some(2),
            ..outbound(10, 1, PEER, 1, "two parts")
        }],
    );
    let state = || message(&store, PEER, "two parts").delivery_state.unwrap();
    assert!(
        deliver(
            &store,
            vec![delivery(
                10,
                1,
                Some(0),
                MobileChatDeliveryState::Acknowledged
            )]
        )
        .is_empty()
    );
    // Half acknowledged is sent.
    assert_eq!(state(), MobileStoredChatDeliveryState::Sent);
    let failures = deliver(
        &store,
        vec![delivery(10, 1, Some(1), MobileChatDeliveryState::Failed)],
    );
    assert_eq!(
        failures,
        vec![MobileStoredChatDeliveryFailureRecord {
            conversation_address: PEER.into(),
            body: "two parts".into(),
            undelivered: false,
        }]
    );
    assert_eq!(state(), MobileStoredChatDeliveryState::Failed);
    // The same word again, and a worse one, cross nothing.
    assert!(
        deliver(
            &store,
            vec![
                delivery(10, 1, Some(1), MobileChatDeliveryState::Failed),
                delivery(10, 1, Some(1), MobileChatDeliveryState::Undelivered),
            ]
        )
        .is_empty()
    );
    assert_eq!(state(), MobileStoredChatDeliveryState::Undelivered);
    // A late acknowledgment wins, and says it was late.
    deliver(
        &store,
        vec![MobileChatDeliveryRecord {
            via_flood: true,
            ..delivery(10, 1, Some(1), MobileChatDeliveryState::Acknowledged)
        }],
    );
    let row = message(&store, PEER, "two parts");
    assert_eq!(
        row.delivery_state,
        Some(MobileStoredChatDeliveryState::Acknowledged)
    );
    assert!(row.delivered_late);
    assert!(row.delivered_flooded);
    // An acknowledgment is final, whatever is said of the frame after it.
    deliver(
        &store,
        vec![delivery(10, 1, Some(1), MobileChatDeliveryState::Failed)],
    );
    assert_eq!(state(), MobileStoredChatDeliveryState::Acknowledged);
}

#[test]
fn undelivered_outranks_failed_and_is_reported_as_such() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![MobileChatMutationRecord {
            fragment_count: Some(2),
            ..outbound(10, 1, PEER, 1, "two parts")
        }],
    );
    let failures = deliver(
        &store,
        vec![
            delivery(10, 1, Some(0), MobileChatDeliveryState::Failed),
            delivery(10, 1, Some(1), MobileChatDeliveryState::Undelivered),
        ],
    );
    // The first record crossed into failure; the second only deepened it.
    assert_eq!(failures.len(), 1);
    assert!(!failures[0].undelivered);
    assert_eq!(
        message(&store, PEER, "two parts").delivery_state,
        Some(MobileStoredChatDeliveryState::Undelivered)
    );

    apply(&store, vec![outbound(10, 2, PEER, 2, "one part")]);
    let failures = deliver(
        &store,
        vec![delivery(10, 2, None, MobileChatDeliveryState::Undelivered)],
    );
    assert!(failures[0].undelivered);
}

#[test]
fn a_fragment_sent_again_is_in_flight_again() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "again")]);
    deliver(
        &store,
        vec![delivery(10, 1, None, MobileChatDeliveryState::Failed)],
    );
    deliver(
        &store,
        vec![delivery(10, 1, None, MobileChatDeliveryState::Sent)],
    );
    assert_eq!(
        message(&store, PEER, "again").delivery_state,
        Some(MobileStoredChatDeliveryState::Sent)
    );
}

#[test]
fn delivery_progress_is_stamped_when_the_first_frame_goes_out() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "progress")]);
    store
        .apply_chat_deliveries(
            OWNER.into(),
            vec![delivery(10, 1, None, MobileChatDeliveryState::Sent)],
            NOW + 10,
        )
        .unwrap();
    store
        .apply_chat_deliveries(
            OWNER.into(),
            vec![delivery(10, 1, None, MobileChatDeliveryState::Acknowledged)],
            NOW + 20,
        )
        .unwrap();
    assert_eq!(
        message(&store, PEER, "progress")
            .repeats
            .unwrap()
            .progress_at_ms,
        NOW + 10
    );
}

#[test]
fn a_reaction_or_an_inbound_row_that_fails_is_not_a_notice() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "target")]);
    apply(
        &store,
        vec![MobileChatMutationRecord {
            message_type: Some(1),
            regarding_handle: Some(1),
            ..outbound(10, 2, PEER, 2, "<3")
        }],
    );
    assert!(
        deliver(
            &store,
            vec![delivery(10, 2, None, MobileChatDeliveryState::Failed)]
        )
        .is_empty()
    );
    // The reaction's state still moved.
    assert_eq!(
        scalar::<String>(
            &store,
            "SELECT delivery_state FROM chat_message WHERE handle = 2"
        ),
        "failed"
    );
    // Evidence about a transmission nothing reports is kept, harmlessly.
    assert!(
        deliver(
            &store,
            vec![delivery(99, 1, None, MobileChatDeliveryState::Failed)]
        )
        .is_empty()
    );
}

#[test]
fn an_edit_re_aims_delivery_at_its_own_frames() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "before")]);
    deliver(
        &store,
        vec![delivery(10, 1, None, MobileChatDeliveryState::Failed)],
    );
    apply(
        &store,
        vec![MobileChatMutationRecord {
            fragment_count: Some(2),
            ..revision(MobileChatMutationKind::Edit, 10, 2, PEER, 1, Some("after"))
        }],
    );
    let row = message(&store, PEER, "after");
    assert_eq!(
        row.delivery_state,
        Some(MobileStoredChatDeliveryState::Pending)
    );
    assert!(!row.delivered_late);
    // The superseded attempt's evidence is gone.
    assert_eq!(
        scalar::<i64>(
            &store,
            "SELECT count(*) FROM chat_delivery_fragment WHERE handle = 1"
        ),
        0
    );
    let pointer: (String, i64, i64) = store
        .connection()
        .query_row(
            "SELECT delivery_session_id, delivery_handle, fragment_count FROM chat_message",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(pointer, ("10".into(), 2, 2));
    // Evidence for the edit's frames reaches the row.
    deliver(
        &store,
        vec![
            delivery(10, 2, Some(0), MobileChatDeliveryState::Acknowledged),
            delivery(10, 2, Some(1), MobileChatDeliveryState::Acknowledged),
        ],
    );
    assert_eq!(
        message(&store, PEER, "after").delivery_state,
        Some(MobileStoredChatDeliveryState::Acknowledged)
    );
    // Evidence for the old compose no longer does.
    deliver(
        &store,
        vec![delivery(10, 1, None, MobileChatDeliveryState::Undelivered)],
    );
    assert_eq!(
        message(&store, PEER, "after").delivery_state,
        Some(MobileStoredChatDeliveryState::Acknowledged)
    );
}

#[test]
fn repeats_that_add_nothing_write_nothing() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "repeated")]);
    let tally = |anonymous_repeats, repeaters: Vec<RouterHintRecord>| MobileChatRepeatRecord {
        session_id: 10,
        handle: 1,
        fragment_index: None,
        repeaters,
        anonymous_repeats,
    };
    store
        .apply_chat_repeats(OWNER.into(), vec![tally(2, vec![hint(&[1, 2])])], NOW)
        .unwrap();
    // Already known, fewer anonymous, and a hint of the wrong width.
    store
        .apply_chat_repeats(
            OWNER.into(),
            vec![tally(1, vec![hint(&[1, 2]), hint(&[1, 2, 3])])],
            NOW + 50,
        )
        .unwrap();
    let repeats = message(&store, PEER, "repeated").repeats.unwrap();
    assert_eq!(repeats.repeaters, [[1, 2]]);
    assert_eq!(repeats.anonymous, 2);
    assert_eq!(repeats.progress_at_ms, NOW);
    // A repeat is only heard of a frame that went out.
    assert_eq!(
        scalar::<String>(&store, "SELECT state FROM chat_delivery_fragment"),
        "sent"
    );
    // Anonymous repeats alone store no named ones, as NULL.
    store
        .apply_chat_repeats(
            OWNER.into(),
            vec![MobileChatRepeatRecord {
                fragment_index: Some(3),
                ..tally(1, vec![])
            }],
            NOW,
        )
        .unwrap();
    assert_eq!(
        scalar::<Option<Vec<u8>>>(
            &store,
            "SELECT repeaters FROM chat_delivery_fragment WHERE fragment_index = 3"
        ),
        None
    );
}

// Resends.

#[test]
fn resend_frames_are_what_is_archived_and_not_yet_acknowledged() {
    let (_directory, store) = open();
    store
        .commit_chat_compose_batch(
            OWNER.into(),
            compose(
                PEER,
                2,
                vec![
                    archive(1, Some(0), &[0xA0]),
                    archive(1, Some(1), &[0xA1]),
                    archive(1, Some(2), &[0xA2]),
                ],
                vec![],
                vec![MobileChatMutationRecord {
                    fragment_count: Some(3),
                    ..outbound(10, 1, PEER, 1, "three parts")
                }],
            ),
            NOW,
        )
        .unwrap();
    deliver(
        &store,
        vec![
            delivery(10, 1, Some(1), MobileChatDeliveryState::Acknowledged),
            delivery(10, 1, Some(0), MobileChatDeliveryState::Failed),
        ],
    );
    let frames = |wire_id| {
        store
            .chat_resend_frames(OWNER.into(), PEER.into(), reference("10", 1), wire_id)
            .unwrap()
    };
    assert_eq!(
        frames(1),
        vec![archive(1, Some(0), &[0xA0]), archive(1, Some(2), &[0xA2])]
    );
    assert_eq!(frames(2), vec![]);

    // An unfragmented message's one entry has no index.
    store
        .commit_chat_compose_batch(
            OWNER.into(),
            compose(
                PEER,
                3,
                vec![archive(2, None, &[0xB0])],
                vec![],
                vec![outbound(10, 2, PEER, 2, "one part")],
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(
        store
            .chat_resend_frames(OWNER.into(), PEER.into(), reference("10", 2), 2)
            .unwrap(),
        vec![archive(2, None, &[0xB0])]
    );
}

#[test]
fn a_resend_moves_delivery_to_its_new_handle_and_keeps_what_was_acknowledged() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![MobileChatMutationRecord {
            fragment_count: Some(3),
            ..outbound(10, 1, PEER, 1, "three parts")
        }],
    );
    deliver(
        &store,
        vec![
            delivery(10, 1, Some(0), MobileChatDeliveryState::Acknowledged),
            delivery(10, 1, Some(1), MobileChatDeliveryState::Failed),
            delivery(10, 1, Some(2), MobileChatDeliveryState::Undelivered),
        ],
    );
    assert_eq!(
        message(&store, PEER, "three parts").delivery_state,
        Some(MobileStoredChatDeliveryState::Undelivered)
    );
    let resend = MobileChatResendRecord {
        message: crate::MobileChatOriginalRef {
            session_id: 10,
            handle: 1,
            wire_id: Some(1),
            epoch: Some(0),
        },
        delivery_session_id: 20,
        delivery_handle: 7,
        forward_secret: true,
    };
    let fragments = || -> Vec<(String, i64, i64, String)> {
        store
            .connection()
            .prepare(
                "SELECT session_id, handle, fragment_index, state FROM chat_delivery_fragment
                ORDER BY session_id, handle, fragment_index",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    store
        .apply_chat_resends(OWNER.into(), vec![resend.clone()], NOW)
        .unwrap();
    let after_one = fragments();
    assert_eq!(after_one, [("20".into(), 7, 0, "acknowledged".into())]);
    let row = message(&store, PEER, "three parts");
    // One of three acknowledged, the rest forgotten: sent.
    assert_eq!(
        row.delivery_state,
        Some(MobileStoredChatDeliveryState::Sent)
    );
    assert!(row.is_forward_secret);
    // Replaying the move lands in the same place.
    store
        .apply_chat_resends(OWNER.into(), vec![resend], NOW)
        .unwrap();
    assert_eq!(fragments(), after_one);

    deliver(
        &store,
        vec![
            delivery(20, 7, Some(1), MobileChatDeliveryState::Acknowledged),
            delivery(20, 7, Some(2), MobileChatDeliveryState::Acknowledged),
        ],
    );
    let row = message(&store, PEER, "three parts");
    assert_eq!(
        row.delivery_state,
        Some(MobileStoredChatDeliveryState::Acknowledged)
    );
    // It recovered from a failure only through the resend's pointer, which
    // started pending.
    assert!(!row.delivered_late);
}

#[test]
fn a_resend_naming_no_message_of_ours_is_skipped() {
    let (_directory, store) = open();
    apply(&store, vec![inbound(10, 1, PEER, 1, "theirs")]);
    let resend = |session_id, handle| MobileChatResendRecord {
        message: crate::MobileChatOriginalRef {
            session_id,
            handle,
            wire_id: None,
            epoch: None,
        },
        delivery_session_id: 20,
        delivery_handle: 1,
        forward_secret: true,
    };
    store
        .apply_chat_resends(OWNER.into(), vec![resend(10, 1), resend(10, 9)], NOW)
        .unwrap();
    let (pointer, secret): ((String, i64), Option<i64>) = store
        .connection()
        .query_row(
            "SELECT delivery_session_id, delivery_handle, forward_secret FROM chat_message",
            [],
            |row| Ok(((row.get(0)?, row.get(1)?), row.get(2)?)),
        )
        .unwrap();
    assert_eq!(pointer, ("10".into(), 1));
    assert_eq!(secret, None);
}

// Failed messages, interrupted deliveries, and gaps.

#[test]
fn removing_a_failed_message_takes_its_reactions_and_evidence_and_nothing_else() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![
            outbound(10, 1, PEER, 1, "failed"),
            outbound(10, 2, PEER, 2, "delivered"),
            MobileChatMutationRecord {
                message_type: Some(1),
                regarding_handle: Some(1),
                ..outbound(10, 3, PEER, 3, "<3")
            },
            MobileChatMutationRecord {
                message_type: Some(1),
                regarding_handle: Some(2),
                ..outbound(10, 4, PEER, 4, "+1")
            },
        ],
    );
    deliver(
        &store,
        vec![
            delivery(10, 1, None, MobileChatDeliveryState::Failed),
            delivery(10, 2, None, MobileChatDeliveryState::Acknowledged),
        ],
    );
    // A delivered message is not touched, nor is another identity's.
    store
        .remove_failed_message(OWNER.into(), reference("10", 2))
        .unwrap();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store
        .remove_failed_message("bob".into(), reference("10", 1))
        .unwrap();
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        4
    );

    store
        .remove_failed_message(OWNER.into(), reference("10", 1))
        .unwrap();
    let left: Vec<String> = transcript(&store, PEER)
        .into_iter()
        .map(|message| message.body)
        .collect();
    assert_eq!(left, ["delivered"]);
    assert_eq!(message(&store, PEER, "delivered").reactions.len(), 1);
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM chat_message"),
        2
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT handle FROM chat_delivery_fragment"),
        2
    );
}

#[test]
fn interrupted_deliveries_settle_by_how_far_they_got() {
    let (_directory, store) = open();
    let channel = "ch:beef";
    apply(
        &store,
        vec![
            outbound(10, 1, PEER, 1, "pending"),
            outbound(10, 2, PEER, 2, "sent"),
            outbound(10, 3, PEER, 3, "acknowledged"),
            outbound(10, 4, channel, 1, "group sent"),
            outbound(10, 5, channel, 2, "group pending"),
        ],
    );
    deliver(
        &store,
        vec![
            delivery(10, 2, None, MobileChatDeliveryState::Sent),
            delivery(10, 3, None, MobileChatDeliveryState::Acknowledged),
            delivery(10, 4, None, MobileChatDeliveryState::Sent),
        ],
    );
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store
        .apply_chat_mutations(
            "bob".into(),
            vec![outbound(10, 1, PEER, 1, "bob's")],
            NOW,
            None,
        )
        .unwrap();
    store.settle_interrupted_deliveries(OWNER.into()).unwrap();
    let state = |address, body| message(&store, address, body).delivery_state.unwrap();
    assert_eq!(
        state(PEER, "pending"),
        MobileStoredChatDeliveryState::Undelivered
    );
    assert_eq!(state(PEER, "sent"), MobileStoredChatDeliveryState::Failed);
    assert_eq!(
        state(PEER, "acknowledged"),
        MobileStoredChatDeliveryState::Acknowledged
    );
    assert_eq!(
        state(channel, "group sent"),
        MobileStoredChatDeliveryState::Sent
    );
    assert_eq!(
        state(channel, "group pending"),
        MobileStoredChatDeliveryState::Undelivered
    );
    assert_eq!(
        scalar::<String>(
            &store,
            "SELECT delivery_state FROM chat_message WHERE owner_identity_id = 'bob'"
        ),
        "pending"
    );
}

#[test]
fn gaps_resolve_unavailable_by_name_or_all_at_once() {
    let (_directory, store) = open();
    let gap = |handle, presence| MobileChatMutationRecord {
        presence,
        ..inbound(10, handle, PEER, handle as u8, "")
    };
    apply(
        &store,
        vec![
            gap(1, MobileChatPresence::GapPending),
            gap(2, MobileChatPresence::GapIdle),
            gap(3, MobileChatPresence::GapPending),
            inbound(10, 4, PEER, 4, "present"),
        ],
    );
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store
        .apply_chat_mutations(
            "bob".into(),
            vec![gap(1, MobileChatPresence::GapPending)],
            NOW,
            None,
        )
        .unwrap();
    let presences = || -> Vec<MobileChatPresence> {
        transcript(&store, PEER)
            .into_iter()
            .map(|message| message.presence)
            .collect()
    };
    let named = |session_id: &str, handle| MobileStoredChatMessageRefRecord {
        session_id: session_id.into(),
        handle,
    };
    store
        .resolve_gaps_unavailable(
            OWNER.into(),
            Some(vec![named("10", 2), named("10", 4), named("99", 3)]),
        )
        .unwrap();
    assert_eq!(
        presences(),
        [
            MobileChatPresence::GapPending,
            MobileChatPresence::Unavailable,
            MobileChatPresence::GapPending,
            MobileChatPresence::Present,
        ]
    );
    store.resolve_gaps_unavailable(OWNER.into(), None).unwrap();
    assert_eq!(
        presences(),
        [
            MobileChatPresence::Unavailable,
            MobileChatPresence::Unavailable,
            MobileChatPresence::Unavailable,
            MobileChatPresence::Present,
        ]
    );
    assert_eq!(
        scalar::<i64>(
            &store,
            "SELECT presence FROM chat_message WHERE owner_identity_id = 'bob'"
        ),
        1
    );
}

// Lookups.

#[test]
fn a_message_s_conversation_is_found_by_its_identity() {
    let (_directory, store) = open();
    apply(&store, vec![outbound(10, 1, PEER, 1, "hi")]);
    assert_eq!(
        store.conversation_address_for_message(OWNER.into(), 10, 1),
        Ok(Some(PEER.into()))
    );
    assert_eq!(
        store.conversation_address_for_message(OWNER.into(), 10, 2),
        Ok(None)
    );
    assert_eq!(
        store.conversation_address_for_message("bob".into(), 10, 1),
        Ok(None)
    );
}

#[test]
fn a_notification_target_is_an_inbound_message_a_person_reads() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![
            MobileChatMutationRecord {
                sender_address: Some("member".into()),
                sender_hint: Some(vec![1, 2, 3]),
                sender_handle: Some("Ridge".into()),
                ..inbound(10, 1, "ch:beef", 1, "hello")
            },
            MobileChatMutationRecord {
                message_type: Some(1),
                ..inbound(10, 2, PEER, 1, "is out")
            },
            outbound(10, 3, PEER, 2, "mine"),
            inbound(10, 4, PEER, 3, ""),
            MobileChatMutationRecord {
                presence: MobileChatPresence::GapPending,
                ..inbound(10, 5, PEER, 4, "gap")
            },
            MobileChatMutationRecord {
                message_type: Some(1),
                regarding_handle: Some(1),
                ..inbound(10, 6, PEER, 5, "<3")
            },
        ],
    );
    let target = |handle| {
        store
            .chat_notification_target(OWNER.into(), 10, handle)
            .unwrap()
    };
    assert_eq!(
        target(1),
        Some(MobileStoredChatNotificationTargetRecord {
            conversation_address: "ch:beef".into(),
            body: "hello".into(),
            sender_address: Some("member".into()),
            sender_hint: Some(vec![1, 2, 3]),
            sender_handle: Some("Ridge".into()),
            is_status: false,
            silent: false,
        })
    );
    assert!(target(2).unwrap().is_status);
    for handle in [3, 4, 5, 6, 7] {
        assert_eq!(target(handle), None, "handle {handle}");
    }
    assert_eq!(
        store.chat_notification_target("bob".into(), 10, 1),
        Ok(None)
    );
}

#[test]
fn a_reaction_notifies_only_on_a_message_of_ours() {
    let (_directory, store) = open();
    let reaction = |handle, regarding, body: &str| MobileChatMutationRecord {
        message_type: Some(1),
        regarding_handle: Some(regarding),
        sender_handle: Some("Ridge".into()),
        ..inbound(10, handle, PEER, handle as u8, body)
    };
    apply(
        &store,
        vec![
            outbound(10, 1, PEER, 1, "ours"),
            inbound(10, 2, PEER, 2, "theirs"),
            reaction(3, 1, "<3"),
            reaction(4, 2, "+1"),
            // A withdrawal.
            reaction(5, 1, ""),
        ],
    );
    let target = |handle| {
        store
            .chat_reaction_notification_target(OWNER.into(), 10, handle)
            .unwrap()
    };
    assert_eq!(
        target(3),
        Some(MobileStoredChatReactionNotificationTargetRecord {
            conversation_address: PEER.into(),
            body: "<3".into(),
            target_body: "ours".into(),
            sender_address: None,
            sender_hint: None,
            sender_handle: Some("Ridge".into()),
        })
    );
    assert_eq!(target(4), None);
    assert_eq!(target(5), None);
    // Not a reaction at all.
    assert_eq!(target(2), None);
    // Nor on a message of ours that was taken back.
    apply(
        &store,
        vec![revision(
            MobileChatMutationKind::Delete,
            10,
            6,
            PEER,
            1,
            None,
        )],
    );
    assert_eq!(target(3), None);
}

#[test]
fn a_resolved_sender_fills_only_rows_that_name_none() {
    let (_directory, store) = open();
    let group = "ch:beef";
    let from = |handle, hint: u8, address: Option<&str>| MobileChatMutationRecord {
        sender_hint: Some(vec![hint; 3]),
        sender_address: address.map(str::to_owned),
        ..inbound(10, handle, group, handle as u8, "hi")
    };
    apply(
        &store,
        vec![
            from(1, 1, None),
            from(2, 1, Some("first")),
            from(3, 2, None),
            MobileChatMutationRecord {
                sender_hint: Some(vec![1; 3]),
                ..inbound(10, 4, "ch:other", 1, "hi")
            },
        ],
    );
    store
        .apply_sender_resolution(
            OWNER.into(),
            MobileChatSenderResolutionRecord {
                conversation_address: group.into(),
                sender_hint: vec![1; 3],
                sender_address: "member".into(),
            },
        )
        .unwrap();
    let senders: Vec<Option<String>> = store
        .connection()
        .prepare("SELECT sender_address FROM chat_message ORDER BY handle")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        senders,
        [Some("member".into()), Some("first".into()), None, None]
    );
}

#[test]
fn checkpoints_list_least_recently_written_first_and_only_the_identity_s() {
    let (_directory, store) = open();
    let commit = |address: &str, next_id, now_ms| {
        store
            .commit_chat_compose_batch(
                OWNER.into(),
                compose(address, next_id, vec![], vec![], vec![]),
                now_ms,
            )
            .unwrap();
    };
    commit("b", 1, 20);
    commit("a", 2, 20);
    commit("c", 3, 10);
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    store
        .commit_chat_compose_batch("bob".into(), compose("z", 9, vec![], vec![], vec![]), 1)
        .unwrap();
    let order: Vec<(String, u8)> = store
        .chat_checkpoints(OWNER.into())
        .unwrap()
        .into_iter()
        .map(|checkpoint| (checkpoint.conversation_address, checkpoint.next_id))
        .collect();
    assert_eq!(order, [("c".into(), 3), ("a".into(), 2), ("b".into(), 1)]);
}

#[test]
fn split_hints_drops_a_trailing_odd_byte() {
    assert_eq!(split_hints(Some(&[1, 2, 3, 4, 5])), [[1, 2], [3, 4]]);
    assert_eq!(split_hints(None), Vec::<Vec<u8>>::new());
}
