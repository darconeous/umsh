//! Deterministic reducer simulations for the text engine: compose, receive,
//! duplication, gaps, repair, fragmentation, resets, and the resend service.

#![cfg(feature = "std")]

use umsh_core::{ChannelId, NodeHint, PublicKey};
use umsh_text::codec;
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveResult, CompletionStatus, ComposeIntent, Destination, Diagnostic, Engine, EngineConfig,
    Event, MutationKind, Output, RepairOutcome, ResolvedRef, destination_for,
};
use umsh_text::validate::{DeliveryPath, DirectChannelProfile, Envelope};
use umsh_text::{
    ConversationKey, Fragment, MessageSequence, MessageType, SenderScope, TextMessage,
};

const LOCAL: PublicKey = PublicKey([0xAA; 32]);
const PEER: PublicKey = PublicKey([0x11; 32]);
const CHANNEL: ChannelId = ChannelId([0x01, 0x02]);
const MEMBER_HINT: NodeHint = NodeHint([0x33, 0x44, 0x55]);

type TestEngine = Engine<DirectChannelProfile, 4, 24>;

fn engine() -> TestEngine {
    Engine::new(DirectChannelProfile, LOCAL, EngineConfig::default(), 42)
}

fn direct_conv() -> ConversationKey {
    ConversationKey::Direct { peer: PEER }
}

fn direct_envelope() -> Envelope {
    Envelope {
        path: DeliveryPath::Unicast,
        conversation: direct_conv(),
        sender: SenderScope::Peer(PEER),
    }
}

fn group_conv() -> ConversationKey {
    ConversationKey::ChannelGroup { channel: CHANNEL }
}

fn group_envelope() -> Envelope {
    Envelope {
        path: DeliveryPath::Multicast,
        conversation: group_conv(),
        sender: SenderScope::ClaimedMember(MEMBER_HINT),
    }
}

/// Drained output with any arena body resolved to an owned string.
#[derive(Debug, Clone)]
enum Drained {
    Transmit {
        destination: Destination,
        payload: Vec<u8>,
    },
    StoreCheckpoint {
        conversation: ConversationKey,
        next_id: u8,
    },
    LookupOutbound {
        request_id: u32,
        conversation: ConversationKey,
        sequence: MessageSequence,
    },
    Insert {
        handle: MessageHandle,
        wire_id: Option<u8>,
        body: String,
        status: CompletionStatus,
        message_type: MessageType,
        regarding: Option<ResolvedRef>,
        client_token: Option<u32>,
        sender_handle: Option<String>,
        bg_color: Option<[u8; 3]>,
        text_color: Option<[u8; 3]>,
    },
    UpdateBody {
        handle: MessageHandle,
        body: String,
        status: CompletionStatus,
    },
    Edit {
        original: ResolvedRef,
        body: String,
    },
    Delete {
        original: ResolvedRef,
    },
    Event(Event),
    Diagnostic(Diagnostic),
}

fn drain(engine: &mut TestEngine) -> Vec<Drained> {
    let mut outputs = Vec::new();
    while let Some(output) = engine.poll_output() {
        outputs.push(match output {
            Output::Transmit(tx) => Drained::Transmit {
                destination: tx.destination,
                payload: tx.payload.to_vec(),
            },
            Output::StoreCheckpoint {
                conversation,
                next_id,
                ..
            } => Drained::StoreCheckpoint {
                conversation,
                next_id,
            },
            Output::LookupOutbound {
                request_id,
                conversation,
                sequence,
            } => Drained::LookupOutbound {
                request_id,
                conversation,
                sequence,
            },
            Output::StoreMessage(mutation) => match mutation.kind {
                MutationKind::Insert {
                    wire_id,
                    body,
                    status,
                    message_type,
                    regarding,
                    client_token,
                    sender_handle,
                    bg_color,
                    text_color,
                    ..
                } => Drained::Insert {
                    handle: mutation.handle,
                    wire_id,
                    body: engine.body(&body).to_string(),
                    status,
                    message_type,
                    regarding,
                    client_token,
                    sender_handle: sender_handle.map(|text| engine.body(&text).to_string()),
                    bg_color,
                    text_color,
                },
                MutationKind::UpdateBody { body, status } => Drained::UpdateBody {
                    handle: mutation.handle,
                    body: engine.body(&body).to_string(),
                    status,
                },
                MutationKind::Edit { original, body } => Drained::Edit {
                    original,
                    body: engine.body(&body).to_string(),
                },
                MutationKind::Delete { original } => Drained::Delete { original },
            },
            Output::Event(event) => Drained::Event(event),
            Output::Diagnostic(diagnostic) => Drained::Diagnostic(diagnostic),
        });
    }
    outputs
}

fn parse_payload(payload: &[u8]) -> umsh_text::OwnedTextMessage {
    umsh_text::OwnedTextMessage::from(codec::parse(payload).expect("transmitted payload parses"))
}

/// Encode a message and feed it to the engine as received traffic.
fn feed(
    engine: &mut TestEngine,
    envelope: &Envelope,
    sender_key: Option<PublicKey>,
    message: &TextMessage<'_>,
    now_ms: u64,
) {
    let mut buffer = [0u8; 512];
    let len = codec::encode(message, &mut buffer).unwrap();
    engine
        .receive(envelope, sender_key, &buffer[..len], now_ms)
        .expect("receive should validate");
}

fn sequenced(id: u8, body: &str) -> TextMessage<'_> {
    let mut message = TextMessage::basic(body);
    message.sequence = Some(MessageSequence::unfragmented(id));
    message
}

fn fragment_msg(id: u8, index: u8, count: u8, body: &[u8]) -> Vec<u8> {
    let mut message = TextMessage::basic("");
    message.sequence = Some(MessageSequence {
        message_id: id,
        fragment: Some(Fragment { index, count }),
    });
    message.body = body;
    let mut buffer = [0u8; 512];
    let len = codec::encode(&message, &mut buffer).unwrap();
    buffer[..len].to_vec()
}

// ---------------------------------------------------------------------
// Compose
// ---------------------------------------------------------------------

#[test]
fn compose_commits_checkpoint_before_transmit_and_announces_reset_once() {
    let mut engine = engine();
    engine
        .compose(
            direct_conv(),
            7,
            ComposeIntent::Text {
                body: "hi",
                status: false,
            },
            0,
        )
        .unwrap();
    let outputs = drain(&mut engine);

    // Checkpoint precedes the transmit.
    assert!(matches!(
        outputs[0],
        Drained::StoreCheckpoint { next_id: 1, .. }
    ));
    let Drained::Transmit {
        destination,
        payload,
    } = &outputs[1]
    else {
        panic!("expected transmit, got {:?}", outputs[1]);
    };
    assert_eq!(*destination, Destination::Peer(PEER));
    let message = parse_payload(payload);
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(0)));
    assert!(message.sequence_reset, "fresh stream announces lazy reset");
    assert_eq!(message.body, b"hi");

    let Drained::Insert {
        client_token,
        wire_id,
        ..
    } = &outputs[2]
    else {
        panic!("expected insert mutation");
    };
    assert_eq!(*client_token, Some(7));
    assert_eq!(*wire_id, Some(0));

    // Second compose: no reset flag, next ID.
    engine
        .compose(
            direct_conv(),
            8,
            ComposeIntent::Text {
                body: "again",
                status: false,
            },
            1,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit { payload, .. } = &outputs[1] else {
        panic!("expected transmit");
    };
    let message = parse_payload(payload);
    assert!(!message.sequence_reset);
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(1)));
}

#[test]
fn restore_checkpoint_continues_without_reset() {
    let mut engine = engine();
    engine.restore(
        &[umsh_text::engine::StreamCheckpoint {
            conversation: direct_conv(),
            next_id: 5,
            epoch: 3,
        }],
        0,
    );
    engine
        .compose(
            direct_conv(),
            1,
            ComposeIntent::Text {
                body: "x",
                status: false,
            },
            0,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit { payload, .. } = &outputs[1] else {
        panic!("expected transmit");
    };
    let message = parse_payload(payload);
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(5)));
    assert!(
        !message.sequence_reset,
        "restored continuity needs no reset"
    );
}

#[test]
fn compose_fragments_large_body() {
    let mut engine = engine();
    let body: String = "x".repeat(400);
    engine
        .compose(
            direct_conv(),
            1,
            ComposeIntent::Text {
                body: &body,
                status: false,
            },
            0,
        )
        .unwrap();
    let outputs = drain(&mut engine);

    let transmits: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            Drained::Transmit { payload, .. } => Some(parse_payload(payload)),
            _ => None,
        })
        .collect();
    assert_eq!(transmits.len(), 3);
    let mut reassembled = Vec::new();
    for (index, message) in transmits.iter().enumerate() {
        let sequence = message.sequence.unwrap();
        let fragment = sequence.fragment.unwrap();
        assert_eq!(fragment.index as usize, index);
        assert_eq!(fragment.count, 3);
        assert_eq!(sequence.message_id, 0);
        if index > 0 {
            // Continuation fragments carry no message-level metadata.
            assert!(!message.sequence_reset);
            assert!(message.sender_handle.is_none());
        }
        reassembled.extend_from_slice(&message.body);
    }
    assert_eq!(reassembled.len(), 400);

    // One insert mutation for the whole logical message.
    assert_eq!(
        outputs
            .iter()
            .filter(|output| matches!(output, Drained::Insert { .. }))
            .count(),
        1
    );
}

#[test]
fn compose_too_large_is_rejected() {
    let mut engine = engine();
    let body: String = "x".repeat(1601);
    assert!(
        engine
            .compose(
                direct_conv(),
                1,
                ComposeIntent::Text {
                    body: &body,
                    status: false
                },
                0
            )
            .is_err()
    );
}

#[test]
fn compose_edit_and_delete_reuse_original_reference() {
    let mut engine = engine();
    let original = engine
        .compose(
            direct_conv(),
            1,
            ComposeIntent::Text {
                body: "v1",
                status: false,
            },
            0,
        )
        .unwrap();
    drain(&mut engine);

    engine
        .compose(
            direct_conv(),
            2,
            ComposeIntent::Edit {
                original,
                body: "v2",
            },
            1,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit { payload, .. } = &outputs[1] else {
        panic!("expected transmit");
    };
    let message = parse_payload(payload);
    assert_eq!(message.editing, Some(0), "edit names the original wire ID");
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(1)));
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Edit { original: ResolvedRef::Handle(handle), .. } if *handle == original
    )));

    engine
        .compose(direct_conv(), 3, ComposeIntent::Delete { original }, 2)
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit { payload, .. } = &outputs[1] else {
        panic!("expected transmit");
    };
    let message = parse_payload(payload);
    assert_eq!(message.editing, Some(0));
    assert!(message.body.is_empty());
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Delete { original: ResolvedRef::Handle(handle) } if *handle == original
    )));
}

#[test]
fn compose_reply_uses_conversation_reference_form() {
    let mut engine = engine();
    // Receive a group message from a member, then emote about it.
    feed(&mut engine, &group_envelope(), None, &sequenced(9, "yo"), 0);
    let outputs = drain(&mut engine);
    let Drained::Insert { handle, .. } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Insert { .. }))
        .unwrap()
    else {
        unreachable!()
    };

    engine
        .compose(
            group_conv(),
            1,
            ComposeIntent::Reply {
                body: "+1",
                regarding: *handle,
                status: true,
            },
            1,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit {
        destination,
        payload,
    } = &outputs[1]
    else {
        panic!("expected transmit");
    };
    assert_eq!(*destination, Destination::Channel(CHANNEL));
    let message = parse_payload(payload);
    assert_eq!(message.message_type, MessageType::Status);
    assert_eq!(
        message.regarding,
        Some(umsh_text::Regarding::Multicast {
            message_id: 9,
            source_prefix: MEMBER_HINT,
        })
    );
}

// ---------------------------------------------------------------------
// Receive: dedup, gaps, wrap, reset
// ---------------------------------------------------------------------

#[test]
fn duplicate_message_is_suppressed() {
    let mut engine = engine();
    feed(&mut engine, &direct_envelope(), None, &sequenced(0, "a"), 0);
    assert_eq!(
        drain(&mut engine)
            .iter()
            .filter(|output| matches!(output, Drained::Insert { .. }))
            .count(),
        1
    );
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(0, "a"),
        10,
    );
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Diagnostic(Diagnostic::DuplicateMessage { message_id: 0 })
    )));
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, Drained::Insert { .. }))
    );
}

#[test]
fn gap_triggers_bounded_repair_after_grace() {
    let mut engine = engine();
    feed(&mut engine, &direct_envelope(), None, &sequenced(0, "a"), 0);
    drain(&mut engine);
    // IDs 1 and 2 lost.
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(3, "d"),
        100,
    );
    drain(&mut engine);

    // Before the grace deadline: nothing.
    engine.tick(500);
    assert!(
        !drain(&mut engine)
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );

    // After grace: one request (per-stream serialization), 1-byte form.
    engine.tick(2200);
    let outputs = drain(&mut engine);
    let requests: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            Drained::Transmit {
                payload,
                destination,
            } => {
                assert_eq!(*destination, Destination::Peer(PEER));
                Some(parse_payload(payload))
            }
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].message_type, MessageType::ResendRequest);
    assert_eq!(requests[0].sequence, Some(MessageSequence::unfragmented(1)));
    assert!(requests[0].body.is_empty());
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Event(Event::RepairStarted { message_id: 1, .. })
    )));

    // The repaired message arrives: RepairFinished, and the next tick moves
    // on to ID 2.
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(1, "b"),
        2300,
    );
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Event(Event::RepairFinished {
            message_id: 1,
            outcome: RepairOutcome::Repaired,
            ..
        })
    )));
    engine.tick(4400);
    let outputs = drain(&mut engine);
    let request = outputs
        .iter()
        .find_map(|output| match output {
            Drained::Transmit { payload, .. } => Some(parse_payload(payload)),
            _ => None,
        })
        .expect("second gap request");
    assert_eq!(request.sequence, Some(MessageSequence::unfragmented(2)));
}

#[test]
fn oversized_gap_rebaselines_without_repair() {
    let mut engine = engine();
    feed(&mut engine, &direct_envelope(), None, &sequenced(0, "a"), 0);
    drain(&mut engine);
    // Gap of 40 messages: beyond the automatic bound.
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(41, "z"),
        100,
    );
    drain(&mut engine);
    engine.tick(60_000);
    assert!(
        !drain(&mut engine)
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );
}

#[test]
fn gap_across_wrap_is_repaired() {
    let mut engine = engine();
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(254, "a"),
        0,
    );
    drain(&mut engine);
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(1, "b"),
        100,
    );
    drain(&mut engine);
    engine.tick(2200);
    let request = drain(&mut engine)
        .iter()
        .find_map(|output| match output {
            Drained::Transmit { payload, .. } => Some(parse_payload(payload)),
            _ => None,
        })
        .expect("wrap gap request");
    assert_eq!(request.sequence, Some(MessageSequence::unfragmented(255)));
}

#[test]
fn sequence_reset_starts_new_epoch_without_backfill() {
    let mut engine = engine();
    feed(&mut engine, &direct_envelope(), None, &sequenced(0, "a"), 0);
    drain(&mut engine);
    let mut reset = sequenced(100, "fresh");
    reset.sequence_reset = true;
    feed(&mut engine, &direct_envelope(), None, &reset, 100);
    let outputs = drain(&mut engine);
    assert!(
        outputs
            .iter()
            .any(|output| matches!(output, Drained::Insert { .. }))
    );
    engine.tick(60_000);
    assert!(
        !drain(&mut engine)
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );
}

#[test]
fn unavailable_accounts_for_gap() {
    let mut engine = engine();
    feed(&mut engine, &direct_envelope(), None, &sequenced(0, "a"), 0);
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(2, "c"),
        50,
    );
    drain(&mut engine);

    let mut unavailable = TextMessage::basic("");
    unavailable.message_type = MessageType::MessageUnavailable;
    unavailable.sequence = Some(MessageSequence::unfragmented(1));
    feed(&mut engine, &direct_envelope(), None, &unavailable, 100);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Event(Event::MessageUnavailable {
            message_id: 1,
            fragment: None,
            ..
        })
    )));
    engine.tick(60_000);
    assert!(
        !drain(&mut engine)
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );
}

// ---------------------------------------------------------------------
// Inbound edits, deletes, replies
// ---------------------------------------------------------------------

#[test]
fn inbound_edit_delete_and_reply_resolve_to_original() {
    let mut engine = engine();
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(0, "v1"),
        0,
    );
    let outputs = drain(&mut engine);
    let Drained::Insert {
        handle: original, ..
    } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Insert { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    let original = *original;

    // Edit.
    let mut edit = sequenced(1, "v2");
    edit.editing = Some(0);
    feed(&mut engine, &direct_envelope(), None, &edit, 10);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Edit { original: ResolvedRef::Handle(handle), body }
            if *handle == original && body == "v2"
    )));

    // Reply from the peer to their own message.
    let mut reply = sequenced(2, "re");
    reply.regarding = Some(umsh_text::Regarding::Unicast { message_id: 0 });
    feed(&mut engine, &direct_envelope(), None, &reply, 20);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Insert { regarding: Some(ResolvedRef::Handle(handle)), .. }
            if *handle == original
    )));

    // Delete (empty edit).
    let mut delete = sequenced(3, "");
    delete.editing = Some(0);
    feed(&mut engine, &direct_envelope(), None, &delete, 30);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Delete { original: ResolvedRef::Handle(handle) } if *handle == original
    )));
}

#[test]
fn ambiguous_one_to_one_reference_stays_unresolved() {
    let mut engine = engine();
    // Both sides used wire ID 0: our own message and the peer's.
    engine
        .compose(
            direct_conv(),
            1,
            ComposeIntent::Text {
                body: "mine",
                status: false,
            },
            0,
        )
        .unwrap();
    drain(&mut engine);
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &sequenced(0, "theirs"),
        10,
    );
    drain(&mut engine);

    let mut reply = sequenced(1, "which?");
    reply.regarding = Some(umsh_text::Regarding::Unicast { message_id: 0 });
    feed(&mut engine, &direct_envelope(), None, &reply, 20);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Insert {
            regarding: Some(ResolvedRef::Unresolved(_)),
            ..
        }
    )));
}

// ---------------------------------------------------------------------
// Fragmentation, partial rendering, fragment repair
// ---------------------------------------------------------------------

#[test]
fn fragmented_message_partial_render_then_completion() {
    let mut engine = engine();
    let envelope = direct_envelope();
    engine
        .receive(&envelope, None, &fragment_msg(5, 0, 3, b"one "), 0)
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Insert {
        handle,
        body,
        status,
        ..
    } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Insert { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    let handle = *handle;
    assert_eq!(body, "one [PENDING]");
    assert!(matches!(status, CompletionStatus::Partial { count: 3, .. }));

    engine
        .receive(&envelope, None, &fragment_msg(5, 2, 3, b"three"), 10)
        .unwrap();
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::UpdateBody { body, .. } if body == "one [PENDING]three"
    )));

    engine
        .receive(&envelope, None, &fragment_msg(5, 1, 3, b"two "), 20)
        .unwrap();
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::UpdateBody { handle: updated, body, status: CompletionStatus::Complete }
            if *updated == handle && body == "one two three"
    )));
}

#[test]
fn stalled_fragment_repair_requests_specific_fragment() {
    let mut engine = engine();
    let envelope = direct_envelope();
    engine
        .receive(&envelope, None, &fragment_msg(5, 0, 3, b"a"), 0)
        .unwrap();
    engine
        .receive(&envelope, None, &fragment_msg(5, 2, 3, b"c"), 10)
        .unwrap();
    drain(&mut engine);

    engine.tick(2500); // past reorder grace: schedule + transmit
    engine.tick(4600); // interval passed: transmit the queued request
    let outputs = drain(&mut engine);
    let request = outputs
        .iter()
        .find_map(|output| match output {
            Drained::Transmit { payload, .. } => Some(parse_payload(payload)),
            _ => None,
        })
        .expect("fragment repair request");
    assert_eq!(request.message_type, MessageType::ResendRequest);
    assert_eq!(
        request.sequence,
        Some(MessageSequence {
            message_id: 5,
            fragment: Some(Fragment { index: 1, count: 3 }),
        })
    );
}

#[test]
fn expired_reassembly_finalizes_with_missing_sentinel() {
    let mut engine = engine();
    let envelope = direct_envelope();
    engine
        .receive(&envelope, None, &fragment_msg(5, 0, 2, b"kept "), 0)
        .unwrap();
    drain(&mut engine);
    engine.tick(200_000);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::UpdateBody { body, status: CompletionStatus::Partial { finalized: true, .. }, .. }
            if body == "kept [MISSING]"
    )));
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Event(Event::RepairFinished {
            outcome: RepairOutcome::Expired,
            ..
        })
    )));
}

#[test]
fn fragment_unavailable_marks_portion_and_settles() {
    let mut engine = engine();
    let envelope = direct_envelope();
    engine
        .receive(&envelope, None, &fragment_msg(5, 0, 2, b"kept "), 0)
        .unwrap();
    drain(&mut engine);

    let mut unavailable = TextMessage::basic("");
    unavailable.message_type = MessageType::MessageUnavailable;
    unavailable.sequence = Some(MessageSequence {
        message_id: 5,
        fragment: Some(Fragment { index: 1, count: 2 }),
    });
    feed(&mut engine, &envelope, None, &unavailable, 100);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::UpdateBody { body, status: CompletionStatus::Partial { finalized: true, .. }, .. }
            if body == "kept [UNAVAILABLE]"
    )));
}

// ---------------------------------------------------------------------
// Group repair: jitter, addressability, cancellation
// ---------------------------------------------------------------------

#[test]
fn group_repair_needs_full_key_and_uses_flagged_blind_unicast() {
    let mut engine = engine();
    let member_key = PublicKey([0x33; 32]);

    // Without the full key: unaddressable, no request ever.
    feed(&mut engine, &group_envelope(), None, &sequenced(0, "a"), 0);
    feed(&mut engine, &group_envelope(), None, &sequenced(2, "c"), 50);
    drain(&mut engine);
    engine.tick(30_000);
    let outputs = drain(&mut engine);
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Event(Event::RepairFinished {
            outcome: RepairOutcome::Unaddressable,
            ..
        })
    )));

    // With the full key: blind-unicast request carrying the group flag.
    let mut engine = engine2();
    feed(
        &mut engine,
        &group_envelope(),
        Some(member_key),
        &sequenced(0, "a"),
        0,
    );
    feed(
        &mut engine,
        &group_envelope(),
        Some(member_key),
        &sequenced(2, "c"),
        50,
    );
    drain(&mut engine);
    engine.tick(50 + 2_000 + 4_000 + 1); // grace + max jitter
    let outputs = drain(&mut engine);
    let (destination, request) = outputs
        .iter()
        .find_map(|output| match output {
            Drained::Transmit {
                destination,
                payload,
            } => Some((*destination, parse_payload(payload))),
            _ => None,
        })
        .expect("group repair request");
    assert_eq!(
        destination,
        Destination::ChannelPeer {
            channel: CHANNEL,
            peer: member_key
        }
    );
    assert!(request.channel_group_resend);
    assert_eq!(request.sequence, Some(MessageSequence::unfragmented(1)));
}

fn engine2() -> TestEngine {
    Engine::new(DirectChannelProfile, LOCAL, EngineConfig::default(), 43)
}

#[test]
fn multicast_arrival_cancels_jittered_group_request() {
    let mut engine = engine();
    let member_key = PublicKey([0x33; 32]);
    feed(
        &mut engine,
        &group_envelope(),
        Some(member_key),
        &sequenced(0, "a"),
        0,
    );
    feed(
        &mut engine,
        &group_envelope(),
        Some(member_key),
        &sequenced(2, "c"),
        50,
    );
    drain(&mut engine);
    // The repaired message is re-multicast before our jittered deadline.
    feed(
        &mut engine,
        &group_envelope(),
        Some(member_key),
        &sequenced(1, "b"),
        100,
    );
    drain(&mut engine);
    engine.tick(30_000);
    assert!(
        !drain(&mut engine)
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );
}

#[test]
fn hint_collision_suppresses_repair() {
    let mut engine = engine();
    let key_a = PublicKey([0x33; 32]);
    let key_b = PublicKey([0x77; 32]);
    feed(
        &mut engine,
        &group_envelope(),
        Some(key_a),
        &sequenced(0, "a"),
        0,
    );
    drain(&mut engine);
    // Same hint resolves to a different key: collision.
    feed(
        &mut engine,
        &group_envelope(),
        Some(key_b),
        &sequenced(5, "z"),
        50,
    );
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Diagnostic(Diagnostic::HintCollision { .. })
    )));
    engine.tick(60_000);
    assert!(
        !drain(&mut engine)
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. }))
    );
}

// ---------------------------------------------------------------------
// Resend service
// ---------------------------------------------------------------------

fn resend_request(id: u8, channel_group: bool) -> TextMessage<'static> {
    let mut message = TextMessage::basic("");
    message.message_type = MessageType::ResendRequest;
    message.sequence = Some(MessageSequence::unfragmented(id));
    message.channel_group_resend = channel_group;
    message
}

#[test]
fn resend_service_answers_found_and_unavailable() {
    let mut engine = engine();
    engine
        .compose(
            direct_conv(),
            1,
            ComposeIntent::Text {
                body: "keep",
                status: false,
            },
            0,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit {
        payload: archived, ..
    } = &outputs[1]
    else {
        panic!("expected transmit");
    };
    let archived = archived.clone();

    // Request for ID 0: engine asks the platform's archive.
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &resend_request(0, false),
        1_000,
    );
    let outputs = drain(&mut engine);
    let Drained::LookupOutbound {
        request_id,
        conversation,
        sequence,
    } = outputs
        .iter()
        .find(|output| matches!(output, Drained::LookupOutbound { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(*conversation, direct_conv());
    assert_eq!(*sequence, MessageSequence::unfragmented(0));

    engine.archive_result(
        *request_id,
        ArchiveResult::Found { payload: &archived },
        1_010,
    );
    let outputs = drain(&mut engine);
    let Drained::Transmit {
        destination,
        payload,
    } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Transmit { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(*destination, Destination::Peer(PEER));
    assert_eq!(*payload, archived, "resend preserves the original payload");

    // A repeat within the coalescing window is ignored.
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &resend_request(0, false),
        2_000,
    );
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Diagnostic(Diagnostic::CoalescedResend { .. })
    )));
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, Drained::LookupOutbound { .. }))
    );

    // Unknown ID: Message Unavailable response.
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &resend_request(9, false),
        3_000,
    );
    let outputs = drain(&mut engine);
    let Drained::LookupOutbound { request_id, .. } = outputs
        .iter()
        .find(|output| matches!(output, Drained::LookupOutbound { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    engine.archive_result(*request_id, ArchiveResult::Unknown, 3_010);
    let outputs = drain(&mut engine);
    let response = outputs
        .iter()
        .find_map(|output| match output {
            Drained::Transmit { payload, .. } => Some(parse_payload(payload)),
            _ => None,
        })
        .expect("unavailable response");
    assert_eq!(response.message_type, MessageType::MessageUnavailable);
    assert_eq!(response.sequence, Some(MessageSequence::unfragmented(9)));
}

#[test]
fn channel_group_resend_returns_by_multicast() {
    let mut engine = engine();
    engine
        .compose(
            group_conv(),
            1,
            ComposeIntent::Text {
                body: "grp",
                status: false,
            },
            0,
        )
        .unwrap();
    drain(&mut engine);

    // Request arrives by blind-unicast with the group flag: it selects the
    // group archive, and the response is re-multicast to the channel.
    let blind = Envelope {
        path: DeliveryPath::BlindUnicast,
        conversation: ConversationKey::ChannelDirect {
            channel: CHANNEL,
            peer: PEER,
        },
        sender: SenderScope::Peer(PEER),
    };
    feed(&mut engine, &blind, None, &resend_request(0, true), 1_000);
    let outputs = drain(&mut engine);
    let Drained::LookupOutbound {
        request_id,
        conversation,
        ..
    } = outputs
        .iter()
        .find(|output| matches!(output, Drained::LookupOutbound { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(
        *conversation,
        group_conv(),
        "flag selects the group archive"
    );

    engine.archive_result(*request_id, ArchiveResult::Evicted, 1_010);
    let outputs = drain(&mut engine);
    let Drained::Transmit { destination, .. } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Transmit { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(*destination, Destination::Channel(CHANNEL));
}

#[test]
fn wrong_stream_request_is_kept_separate() {
    let mut engine = engine();
    // Compose only in the channel-direct conversation.
    let direct = ConversationKey::ChannelDirect {
        channel: CHANNEL,
        peer: PEER,
    };
    engine
        .compose(
            direct,
            1,
            ComposeIntent::Text {
                body: "cd",
                status: false,
            },
            0,
        )
        .unwrap();
    drain(&mut engine);

    // A flagged (group) request for the same numeric ID selects the group
    // stream, not the channel-direct stream.
    let blind = Envelope {
        path: DeliveryPath::BlindUnicast,
        conversation: direct,
        sender: SenderScope::Peer(PEER),
    };
    feed(&mut engine, &blind, None, &resend_request(0, true), 1_000);
    let outputs = drain(&mut engine);
    let Drained::LookupOutbound { conversation, .. } = outputs
        .iter()
        .find(|output| matches!(output, Drained::LookupOutbound { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(*conversation, group_conv());
}

#[test]
fn destinations_follow_conversation_delivery_mode() {
    assert_eq!(destination_for(&direct_conv()), Destination::Peer(PEER));
    assert_eq!(
        destination_for(&group_conv()),
        Destination::Channel(CHANNEL)
    );
    assert_eq!(
        destination_for(&ConversationKey::ChannelDirect {
            channel: CHANNEL,
            peer: PEER
        }),
        Destination::ChannelPeer {
            channel: CHANNEL,
            peer: PEER
        }
    );
    assert_eq!(
        destination_for(&ConversationKey::Room { room: PEER }),
        Destination::Peer(PEER)
    );
}

// ---------------------------------------------------------------------
// Review regressions (2026-07-17)
// ---------------------------------------------------------------------

#[test]
fn oversized_fragment_is_salvaged_as_unavailable() {
    let mut engine = engine();

    // Fragment zero announces the assembly.
    feed_fragment(&mut engine, 0, 0, 3, b"AB ", 0);
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Insert { body, .. } if body == "AB [PENDING]"
    )));

    // An oversized fragment 1 marks only itself unavailable; the message
    // survives and the remaining fragment stays independently repairable.
    let body = [b'a'; 200];
    let payload = fragment_msg(0, 1, 3, &body);
    engine
        .receive(&direct_envelope(), None, &payload, 1)
        .expect("syntactically valid; salvaged by the engine, not rejected");
    let outputs = drain(&mut engine);
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Diagnostic(Diagnostic::OversizedFragment {
            message_id: 0,
            fragment: 1,
        })
    )));
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            Drained::UpdateBody { body, .. } if body == "AB [UNAVAILABLE][PENDING]"
        )),
        "the disclaimed portion shows immediately, split from the pending run: {outputs:?}"
    );

    // The last valid fragment settles the slot: final render, no TTL wait.
    feed_fragment(&mut engine, 0, 2, 3, b"CD", 2);
    let outputs = drain(&mut engine);
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            Drained::UpdateBody {
                body,
                status: CompletionStatus::Partial {
                    finalized: true,
                    ..
                },
                ..
            } if body == "AB [UNAVAILABLE]CD"
        )),
        "settled salvage finalizes with the valid fragments intact: {outputs:?}"
    );

    // No repair ever fires for the oversized fragment.
    engine.tick(60_000);
    let outputs = drain(&mut engine);
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, Drained::Transmit { .. })),
        "no repair request for an unavailable-marked fragment: {outputs:?}"
    );
}

#[test]
fn oversized_fragment_zero_still_contributes_its_options() {
    let mut engine = engine();
    // The continuation arrives first; the assembly stays unannounced.
    feed_fragment(&mut engine, 0, 1, 2, b"tail", 0);
    drain(&mut engine);

    // Fragment zero has valid, authenticated options but an oversized body.
    let big = [b'x'; 200];
    let mut first = TextMessage::basic("");
    first.sequence = Some(MessageSequence {
        message_id: 0,
        fragment: Some(Fragment { index: 0, count: 2 }),
    });
    first.sender_handle = Some("alice");
    first.body = &big;
    let mut buffer = [0u8; 512];
    let len = codec::encode(&first, &mut buffer).unwrap();
    engine
        .receive(&direct_envelope(), None, &buffer[..len], 1)
        .expect("oversized fragment zero is salvaged");
    let outputs = drain(&mut engine);

    let Some(Drained::Insert {
        sender_handle,
        body,
        ..
    }) = outputs
        .iter()
        .find(|output| matches!(output, Drained::Insert { .. }))
    else {
        panic!("metadata from the oversized fragment zero should announce: {outputs:?}");
    };
    assert_eq!(sender_handle.as_deref(), Some("alice"));
    assert_eq!(body, "[UNAVAILABLE]tail");
    // Settled immediately: fragment 0 unavailable, fragment 1 present.
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            Drained::UpdateBody {
                status: CompletionStatus::Partial {
                    finalized: true,
                    ..
                },
                ..
            }
        )),
        "{outputs:?}"
    );
}

#[test]
fn sequence_reset_on_continuation_is_ignored() {
    let mut engine = engine();
    feed(
        &mut engine,
        &direct_envelope(),
        None,
        &{
            let mut message = TextMessage::basic("");
            message.sequence = Some(MessageSequence {
                message_id: 0,
                fragment: Some(Fragment { index: 0, count: 2 }),
            });
            message.body = b"first ";
            message
        },
        0,
    );
    drain(&mut engine);

    // A malformed continuation carrying Sequence Reset must not destroy the
    // in-progress assembly.
    let mut continuation = TextMessage::basic("");
    continuation.sequence = Some(MessageSequence {
        message_id: 0,
        fragment: Some(Fragment { index: 1, count: 2 }),
    });
    continuation.sequence_reset = true;
    continuation.body = b"second";
    feed(&mut engine, &direct_envelope(), None, &continuation, 10);
    let outputs = drain(&mut engine);

    assert!(
        outputs.iter().any(|output| matches!(
            output,
            Drained::UpdateBody { body, status: CompletionStatus::Complete, .. }
                if body == "first second"
        )),
        "assembly must complete despite the stray reset flag: {outputs:?}"
    );
    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Diagnostic(Diagnostic::IgnoredContinuationMetadata { message_id: 0 })
    )));
}

#[test]
fn fragment_zero_metadata_survives_reassembly() {
    let mut engine = engine();
    // A handle longer than any retention bound: it must arrive untruncated,
    // exactly as it would for an unfragmented message.
    let handle = "a".repeat(70);
    let mut first = TextMessage::basic("");
    first.sequence = Some(MessageSequence {
        message_id: 0,
        fragment: Some(Fragment { index: 0, count: 2 }),
    });
    first.sender_handle = Some(&handle);
    first.bg_color = Some([0x10, 0x20, 0x30]);
    first.text_color = Some([0xEE, 0xEE, 0xEE]);
    first.body = b"hello ";
    feed(&mut engine, &direct_envelope(), None, &first, 0);
    let outputs = drain(&mut engine);

    let Some(Drained::Insert {
        sender_handle,
        bg_color,
        text_color,
        ..
    }) = outputs
        .iter()
        .find(|output| matches!(output, Drained::Insert { .. }))
    else {
        panic!("fragment zero should announce the message: {outputs:?}");
    };
    assert_eq!(sender_handle.as_deref(), Some(handle.as_str()));
    assert_eq!(*bg_color, Some([0x10, 0x20, 0x30]));
    assert_eq!(*text_color, Some([0xEE, 0xEE, 0xEE]));
}

#[test]
fn fully_unavailable_run_renders_unavailable_before_settling() {
    let mut engine = engine();
    feed_fragment(&mut engine, 0, 0, 4, b"a", 0);
    feed_fragment(&mut engine, 0, 2, 4, b"c", 1);
    drain(&mut engine);

    // Fragment 1 is disclaimed while fragment 3 is still repairable.
    let mut unavailable = TextMessage::basic("");
    unavailable.message_type = MessageType::MessageUnavailable;
    unavailable.sequence = Some(MessageSequence {
        message_id: 0,
        fragment: Some(Fragment { index: 1, count: 4 }),
    });
    feed(&mut engine, &direct_envelope(), None, &unavailable, 10);
    let outputs = drain(&mut engine);

    let Some(Drained::UpdateBody { body, status, .. }) = outputs
        .iter()
        .find(|output| matches!(output, Drained::UpdateBody { .. }))
    else {
        panic!("the disclaimed fragment should rerender the message: {outputs:?}");
    };
    assert!(
        body.contains("[UNAVAILABLE]") && body.contains("[PENDING]"),
        "unavailable run shows immediately while the repairable gap stays pending: {body:?}"
    );
    assert!(matches!(
        status,
        CompletionStatus::Partial {
            finalized: false,
            ..
        }
    ));
}

#[test]
fn outbound_continuity_survives_eviction_and_deep_restore() {
    let mut engine = engine();
    let conversations: Vec<ConversationKey> = (0..10)
        .map(|index| ConversationKey::Direct {
            peer: PublicKey([index as u8 + 1; 32]),
        })
        .collect();
    let checkpoints: Vec<umsh_text::engine::StreamCheckpoint> = conversations
        .iter()
        .enumerate()
        .map(
            |(index, conversation)| umsh_text::engine::StreamCheckpoint {
                conversation: *conversation,
                next_id: index as u8 + 10,
                epoch: 1,
            },
        )
        .collect();
    // More checkpoints than the active-stream capacity of 8.
    engine.restore(&checkpoints, 0);

    // The deepest checkpoint is honored.
    engine
        .compose(
            conversations[9],
            1,
            ComposeIntent::Text {
                body: "x",
                status: false,
            },
            0,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit { payload, .. } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Transmit { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    let message = parse_payload(payload);
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(19)));
    assert!(
        !message.sequence_reset,
        "restored continuity needs no reset"
    );

    // Activate enough other conversations to evict conversation 9.
    for (index, conversation) in conversations[..9].iter().enumerate() {
        engine
            .compose(
                *conversation,
                index as u32,
                ComposeIntent::Text {
                    body: "y",
                    status: false,
                },
                100 + index as u64,
            )
            .unwrap();
        drain(&mut engine);
    }

    // The evicted stream resumes its persisted sequence instead of resetting.
    engine
        .compose(
            conversations[9],
            2,
            ComposeIntent::Text {
                body: "z",
                status: false,
            },
            1_000,
        )
        .unwrap();
    let outputs = drain(&mut engine);
    let Drained::Transmit { payload, .. } = outputs
        .iter()
        .find(|output| matches!(output, Drained::Transmit { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    let message = parse_payload(payload);
    assert_eq!(message.sequence, Some(MessageSequence::unfragmented(20)));
    assert!(
        !message.sequence_reset,
        "an evicted stream must not reset when its continuity was stashed"
    );
}

#[test]
fn complete_reassembly_with_invalid_utf8_is_diagnosed() {
    let mut engine = engine();
    feed_fragment(&mut engine, 0, 0, 2, b"ok\xFF", 0);
    drain(&mut engine);
    feed_fragment(&mut engine, 0, 1, 2, b"end", 1);
    let outputs = drain(&mut engine);

    assert!(outputs.iter().any(|output| matches!(
        output,
        Drained::Diagnostic(Diagnostic::ReassembledInvalidUtf8 { message_id: 0 })
    )));
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            Drained::UpdateBody { body, status: CompletionStatus::Complete, .. }
                if body == "ok\u{FFFD}end"
        )),
        "the complete body renders lossily alongside the diagnostic: {outputs:?}"
    );
}

/// Encode and feed one fragment of `id` on the direct conversation.
fn feed_fragment(engine: &mut TestEngine, id: u8, index: u8, count: u8, body: &[u8], now_ms: u64) {
    let payload = fragment_msg(id, index, count, body);
    engine
        .receive(&direct_envelope(), None, &payload, now_ms)
        .expect("fragment should validate");
}
