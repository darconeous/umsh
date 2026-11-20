use rusqlite::params;

use crate::mobile_chat::{
    MobileChatDeliveryState, MobileChatDirection, MobileChatMutationKind, MobileChatMutationRecord,
};

use super::super::chat_test_support::*;
use super::*;

const PEER: &str = "peer";

/// `checkReplies`: a reply quotes its original as that reads now: found by
/// live handle or by wire coordinates, adopted when it arrives after the
/// reply, shown as deleted once taken back, and unavailable when it never
/// comes.
#[test]
fn the_smoke_test_s_reply_checks() {
    let (_directory, store) = open();
    let peer = "reply-peer";
    let reply =
        |session, handle, wire_id, body: &str, regarding_wire_id| MobileChatMutationRecord {
            regarding_wire_id: Some(regarding_wire_id),
            regarding_direction: Some(MobileChatDirection::Inbound),
            ..inbound(session, handle, peer, wire_id, body)
        };
    let rows = || -> HashMap<String, MobileStoredChatMessageRecord> {
        transcript(&store, peer)
            .into_iter()
            .map(|message| (message.body.clone(), message))
            .collect()
    };

    apply(
        &store,
        vec![
            inbound(100, 1, peer, 5, "Is the repeater up?"),
            // Same session: named by its live handle.
            MobileChatMutationRecord {
                regarding_handle: Some(1),
                ..outbound(100, 2, peer, 1, "Since this morning.")
            },
        ],
    );
    apply(
        &store,
        vec![
            // A later session: named by wire coordinates.
            reply(200, 1, 6, "Three hops?", 5),
            // Ahead of its original.
            reply(200, 2, 8, "Bring the antenna.", 7),
            // Never answered by anything stored.
            reply(200, 3, 9, "Ten minutes late.", 77),
            // A gap that turns out to be a reply once repaired.
            MobileChatMutationRecord {
                presence: MobileChatPresence::GapPending,
                ..inbound(200, 4, peer, 10, "")
            },
        ],
    );
    let mut rows_now = rows();
    let original = |rows: &HashMap<String, MobileStoredChatMessageRecord>, body: &str| {
        rows[body]
            .quote
            .as_ref()
            .and_then(|quote| quote.original.clone())
    };
    assert_eq!(
        original(&rows_now, "Since this morning.").unwrap().body,
        "Is the repeater up?"
    );
    assert_eq!(
        original(&rows_now, "Three hops?").unwrap().reference,
        MobileStoredChatMessageRefRecord {
            session_id: "100".into(),
            handle: 1,
        }
    );
    assert!(rows_now["Bring the antenna."].is_reply);
    assert_eq!(original(&rows_now, "Bring the antenna."), None);
    assert_eq!(
        rows_now["Ten minutes late."].quote,
        Some(MobileStoredChatQuoteRecord { original: None })
    );
    assert_eq!(
        rows_now["Is the repeater up?"].quote, None,
        "an original is not a reply"
    );

    apply(
        &store,
        vec![
            inbound(200, 5, peer, 7, "The antenna is in the truck."),
            MobileChatMutationRecord {
                revision: 1,
                ..reply(200, 4, 10, "Filled in.", 7)
            },
            revision(MobileChatMutationKind::Delete, 100, 6, peer, 1, None),
        ],
    );
    rows_now = rows();
    assert_eq!(
        original(&rows_now, "Bring the antenna.").unwrap().body,
        "The antenna is in the truck.",
        "a reply that outran its original adopts it"
    );
    assert_eq!(
        original(&rows_now, "Filled in.").unwrap().reference,
        MobileStoredChatMessageRefRecord {
            session_id: "200".into(),
            handle: 5,
        }
    );
    assert!(original(&rows_now, "Three hops?").unwrap().is_deleted);
}

#[test]
fn a_quote_of_a_gap_or_a_missing_reference_is_unavailable() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![
            MobileChatMutationRecord {
                presence: MobileChatPresence::GapIdle,
                ..inbound(10, 1, PEER, 4, "")
            },
            MobileChatMutationRecord {
                regarding_handle: Some(1),
                ..inbound(10, 2, PEER, 5, "about a gap")
            },
            // Says it replies, in a form this phone could not read.
            MobileChatMutationRecord {
                regarding_unknown: true,
                ..inbound(10, 3, PEER, 6, "about something")
            },
        ],
    );
    for body in ["about a gap", "about something"] {
        let row = message(&store, PEER, body);
        assert!(row.is_reply, "{body}");
        assert_eq!(
            row.quote,
            Some(MobileStoredChatQuoteRecord { original: None }),
            "{body}"
        );
    }
    assert_eq!(
        message(&store, PEER, "about a gap")
            .reply_target
            .unwrap()
            .handle,
        1
    );
}

fn react(
    session_id: u64,
    handle: u32,
    regarding: u32,
    body: &str,
    direction: MobileChatDirection,
    sender: (Option<&str>, Option<&[u8]>),
) -> MobileChatMutationRecord {
    MobileChatMutationRecord {
        message_type: Some(1),
        regarding_handle: Some(regarding),
        sender_address: sender.0.map(str::to_owned),
        sender_hint: sender.1.map(<[u8]>::to_vec),
        body: Some(body.into()),
        wire_id: Some(handle as u8),
        ..insert(session_id, handle, PEER, direction)
    }
}

#[test]
fn reactions_fold_to_each_sender_s_newest_and_a_withdrawal_removes_it() {
    let (_directory, store) = open();
    use MobileChatDirection::{Inbound, Outbound};
    apply(&store, vec![inbound(10, 1, PEER, 1, "target")]);
    // Each in its own batch, so arrival order is the rowid order the fold
    // reads.
    for mutation in [
        react(10, 2, 1, "<3", Inbound, (Some("ann"), None)),
        react(10, 3, 1, "+1", Inbound, (None, Some(&[0xAB, 0xCD, 0x01]))),
        react(10, 4, 1, "ha", Outbound, (None, None)),
        // Ann changes hers; ours is replaced, then withdrawn.
        react(10, 5, 1, "!", Inbound, (Some("ann"), None)),
        react(10, 6, 1, "?", Outbound, (None, None)),
        react(10, 7, 1, "", Outbound, (None, None)),
        // A member known by hint only is not another member with an address.
        react(10, 8, 1, "-1", Inbound, (None, Some(&[0xAB, 0xCD, 0x02]))),
        // Anyone else: one unnamed peer.
        react(10, 9, 1, "<3", Inbound, (None, None)),
    ] {
        apply(&store, vec![mutation]);
    }
    let reactions: Vec<(String, u32)> = message(&store, PEER, "target")
        .reactions
        .into_iter()
        .map(|reaction| (reaction.body, reaction.reference.handle))
        .collect();
    // In the order each sender was first heard; each sender's newest.
    assert_eq!(
        reactions,
        [
            ("!".into(), 5),
            ("+1".into(), 3),
            ("-1".into(), 8),
            ("<3".into(), 9)
        ]
    );
    // A deleted reaction is no reaction.
    apply(
        &store,
        vec![revision(
            MobileChatMutationKind::Delete,
            10,
            10,
            PEER,
            5,
            None,
        )],
    );
    let bodies: Vec<String> = message(&store, PEER, "target")
        .reactions
        .into_iter()
        .map(|reaction| reaction.body)
        .collect();
    // Ann's newest live one is now her first.
    assert_eq!(bodies, ["<3", "+1", "-1", "<3"]);
}

#[test]
fn a_reaction_of_ours_carries_its_delivery_and_secrecy() {
    let (_directory, store) = open();
    apply(
        &store,
        vec![
            inbound(10, 1, PEER, 1, "target"),
            MobileChatMutationRecord {
                forward_secret: Some(true),
                epoch: Some(9),
                ..react(10, 2, 1, "<3", MobileChatDirection::Outbound, (None, None))
            },
            MobileChatMutationRecord {
                forward_secret: Some(true),
                ..react(
                    10,
                    3,
                    1,
                    "+1",
                    MobileChatDirection::Inbound,
                    (Some("ann"), None),
                )
            },
        ],
    );
    store
        .apply_chat_deliveries(
            OWNER.into(),
            vec![chat_delivery(10, 2, MobileChatDeliveryState::Acknowledged)],
            NOW,
        )
        .unwrap();
    let reactions = message(&store, PEER, "target").reactions;
    assert_eq!(
        reactions[0],
        MobileStoredChatReactionRecord {
            body: "<3".into(),
            outbound: true,
            sender_address: None,
            sender_hint: None,
            reference: reference("10", 2),
            wire_id: Some(2),
            epoch: Some(9),
            created_at_ms: NOW,
            delivery_state: Some(MobileStoredChatDeliveryState::Acknowledged),
            forward_secret: true,
        }
    );
    // Only ours say so.
    assert!(!reactions[1].forward_secret);
}

fn chat_delivery(
    session_id: u64,
    handle: u32,
    state: MobileChatDeliveryState,
) -> crate::mobile_chat::MobileChatDeliveryRecord {
    delivery(session_id, handle, None, state)
}

/// Seed `count` messages into `address` straight into the table, in
/// same-millisecond clusters the way the store stamps a batch, so the
/// rowid half of the cursor carries weight. Every row is derived from its
/// index.
fn seed(store: &MobileAppStore, owner: &str, address: &str, session_id: &str, count: u32) {
    let connection = store.connection();
    let mut statement = connection
        .prepare(
            "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                conversation_address, direction, body, deleted, created_at_ms, presence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .unwrap();
    let mut created_at_ms = 1_700_000_000_000i64;
    let mut cluster_remaining = 0;
    for index in 0..count {
        if cluster_remaining == 0 {
            cluster_remaining = 3 + index % 6;
            created_at_ms += 60_000 + i64::from(index % 997) * 311;
        }
        cluster_remaining -= 1;
        let presence = if index % 89 == 0 {
            1
        } else if index % 211 == 0 {
            2
        } else {
            0
        };
        statement
            .execute(params![
                owner,
                session_id,
                index,
                address,
                index % 3 == 0,
                format!("message {index}"),
                index % 97 == 0,
                created_at_ms,
                presence,
            ])
            .unwrap();
    }
}

fn handles(page: &MobileStoredChatMessagePageRecord) -> Vec<u32> {
    page.messages
        .iter()
        .map(|message| message.reference.handle)
        .collect()
}

/// The scale benchmark's correctness half, at a size a unit test affords:
/// a full backward walk reassembles the transcript, the newest page is its
/// tail, a window is the contiguous slice around its anchor, and an
/// inclusive forward read starts at its own cursor.
#[test]
fn the_smoke_test_s_paging_checks() {
    let (_directory, store) = open();
    let deep = "deep";
    seed(&store, OWNER, deep, "1000", 700);
    seed(&store, OWNER, "other", "1001", 20);

    let mut page = store
        .chat_message_page_newest(OWNER.into(), deep.into(), 150)
        .unwrap();
    assert!(!page.has_newer, "the newest page is at the live edge");
    let mut walked = page.messages.clone();
    let mut pages = 1;
    while page.has_older {
        let oldest = page.messages[0].cursor();
        page = store
            .chat_message_page_before(OWNER.into(), deep.into(), oldest, 150)
            .unwrap();
        assert!(page.has_newer, "a page before a cursor always has newer");
        walked.splice(0..0, page.messages.iter().cloned());
        pages += 1;
    }
    assert_eq!(pages, 5);
    assert_eq!(
        walked
            .iter()
            .map(|message| message.reference.handle)
            .collect::<Vec<_>>(),
        (0..700).collect::<Vec<_>>(),
        "the walk lost, repeated, or reordered rows"
    );
    assert!(
        walked
            .windows(2)
            .all(|pair| pair[0].cursor() < pair[1].cursor()),
        "cursors increase strictly in transcript order"
    );
    // Ties in the millisecond are the normal case here.
    assert!(
        walked
            .windows(2)
            .any(|pair| pair[0].created_at_ms == pair[1].created_at_ms)
    );

    let newest = store
        .chat_message_page_newest(OWNER.into(), deep.into(), 150)
        .unwrap();
    assert_eq!(handles(&newest), (550..700).collect::<Vec<_>>());
    assert!(newest.has_older);

    let anchor = &walked[350];
    let window = store
        .chat_message_window(OWNER.into(), deep.into(), anchor.reference.clone(), 75)
        .unwrap()
        .unwrap();
    assert_eq!(handles(&window), (275..=425).collect::<Vec<_>>());
    assert!(window.has_older && window.has_newer);
    // A message of another conversation is a stale hit, not a fault.
    assert_eq!(
        store.chat_message_window(OWNER.into(), "other".into(), anchor.reference.clone(), 75),
        Ok(None)
    );

    let extent = store
        .chat_message_page_after(OWNER.into(), deep.into(), walked[100].cursor(), 150, true)
        .unwrap();
    assert_eq!(handles(&extent), (100..250).collect::<Vec<_>>());
    assert!(extent.has_older && extent.has_newer);
    let after = store
        .chat_message_page_after(OWNER.into(), deep.into(), walked[100].cursor(), 150, false)
        .unwrap();
    assert_eq!(handles(&after), (101..251).collect::<Vec<_>>());
}

#[test]
fn page_flags_are_exact_at_the_boundaries() {
    let (_directory, store) = open();
    seed(&store, OWNER, PEER, "1", 10);
    let newest = |limit| {
        store
            .chat_message_page_newest(OWNER.into(), PEER.into(), limit)
            .unwrap()
    };
    // Exactly everything: nothing older.
    let all = newest(10);
    assert_eq!(handles(&all), (0..10).collect::<Vec<_>>());
    assert!(!all.has_older && !all.has_newer);
    let short = newest(9);
    assert_eq!(handles(&short), (1..10).collect::<Vec<_>>());
    assert!(short.has_older);
    // A request for nothing reads one.
    assert_eq!(handles(&newest(0)), [9]);

    let cursor = all.messages[5].cursor();
    let before = |limit| {
        store
            .chat_message_page_before(OWNER.into(), PEER.into(), cursor, limit)
            .unwrap()
    };
    assert_eq!(handles(&before(5)), (0..5).collect::<Vec<_>>());
    assert!(!before(5).has_older);
    assert!(before(4).has_older);
    assert!(before(5).has_newer);
    let after = |including, limit| {
        store
            .chat_message_page_after(OWNER.into(), PEER.into(), cursor, limit, including)
            .unwrap()
    };
    assert_eq!(handles(&after(false, 4)), (6..10).collect::<Vec<_>>());
    assert!(!after(false, 4).has_newer);
    assert!(after(false, 3).has_newer);
    assert!(after(false, 4).has_older);
    assert!(after(true, 5).has_older);
    // Past the end there is nothing, and a forward read with nothing to
    // show answers nothing about what is behind it.
    let edge = all.messages[9].cursor();
    let past = store
        .chat_message_page_after(OWNER.into(), PEER.into(), edge, 5, false)
        .unwrap();
    assert_eq!(past, MobileStoredChatMessagePageRecord::default());
    // From the first message, nothing is older.
    let first = store
        .chat_message_page_after(OWNER.into(), PEER.into(), all.messages[0].cursor(), 3, true)
        .unwrap();
    assert!(!first.has_older);

    // A window at either edge is bounded only on the other side.
    let window = |handle, radius| {
        store
            .chat_message_window(OWNER.into(), PEER.into(), reference("1", handle), radius)
            .unwrap()
            .unwrap()
    };
    let start = window(0, 3);
    assert_eq!(handles(&start), [0, 1, 2, 3]);
    assert!(!start.has_older && start.has_newer);
    let end = window(9, 3);
    assert_eq!(handles(&end), [6, 7, 8, 9]);
    assert!(end.has_older && !end.has_newer);
    let whole = window(5, 20);
    assert_eq!(handles(&whole), (0..10).collect::<Vec<_>>());
    assert!(!whole.has_older && !whole.has_newer);
}

#[test]
fn a_page_is_held_to_five_hundred() {
    let (_directory, store) = open();
    seed(&store, OWNER, PEER, "1", 502);
    let page = store
        .chat_message_page_newest(OWNER.into(), PEER.into(), u32::MAX)
        .unwrap();
    assert_eq!(page.messages.len(), 500);
    assert!(page.has_older);
    assert_eq!(page.messages[0].reference.handle, 2);
}

#[test]
fn the_same_instant_orders_by_arrival() {
    let (_directory, store) = open();
    // One batch: one instant, so the row order decides.
    apply(
        &store,
        (0..5)
            .map(|handle| inbound(10, 4 - handle, PEER, handle as u8, &format!("m{handle}")))
            .collect(),
    );
    let bodies: Vec<String> = transcript(&store, PEER)
        .into_iter()
        .map(|message| message.body)
        .collect();
    assert_eq!(bodies, ["m0", "m1", "m2", "m3", "m4"]);
    let page = store
        .chat_message_page_newest(OWNER.into(), PEER.into(), 2)
        .unwrap();
    let bodies: Vec<&str> = page
        .messages
        .iter()
        .map(|message| message.body.as_str())
        .collect();
    assert_eq!(bodies, ["m3", "m4"]);
}

#[test]
fn reads_see_only_the_identity_s_own_conversation_and_no_reactions() {
    let (_directory, store) = open();
    store
        .insert_identity("bob".into(), "bob-public".into(), 1)
        .unwrap();
    seed(&store, OWNER, PEER, "1", 3);
    seed(&store, "bob", PEER, "1", 5);
    seed(&store, OWNER, "other", "2", 4);
    apply(
        &store,
        vec![react(
            1,
            100,
            0,
            "<3",
            MobileChatDirection::Inbound,
            (None, None),
        )],
    );
    // The seeded rows and the reaction share session "1", so the reaction
    // lands on handle 0.
    let page = store
        .chat_message_page_newest(OWNER.into(), PEER.into(), 50)
        .unwrap();
    assert_eq!(handles(&page), [0, 1, 2]);
    assert_eq!(page.messages[0].reactions.len(), 1);
    assert_eq!(store.chat_message_count(OWNER.into(), PEER.into()), Ok(3));
    assert_eq!(store.chat_message_count("bob".into(), PEER.into()), Ok(5));
    // Bob's reactions are not Alice's, though they name the same handle.
    assert_eq!(
        store
            .chat_message_page_newest("bob".into(), PEER.into(), 50)
            .unwrap()
            .messages[0]
            .reactions,
        vec![]
    );
    // A cursor is found only in its own conversation, for its own identity.
    let cursor = |owner: &str, address: &str| {
        store
            .chat_message_cursor(owner.into(), address.into(), reference("1", 0))
            .unwrap()
    };
    assert_eq!(cursor(OWNER, PEER), Some(page.messages[0].cursor()));
    assert_eq!(cursor(OWNER, "other"), None);
    assert_ne!(cursor("bob", PEER), cursor(OWNER, PEER));
    // The lookup is by identity alone, as the Swift store's is: a reaction
    // has one too.
    assert_eq!(
        store.chat_message_cursor(OWNER.into(), PEER.into(), reference("1", 100)),
        Ok(Some(MobileStoredChatCursorRecord {
            created_at_ms: NOW,
            row_id: scalar(&store, "SELECT rowid FROM chat_message WHERE handle = 100"),
        }))
    );
}

#[test]
fn a_message_reads_back_every_column_it_was_stored_with() {
    let (_directory, store) = open();
    store
        .connection()
        .execute(
            "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                conversation_address, direction, body, created_at_ms, wire_id, epoch,
                delivery_state, edited, presence, received_late, delivered_late,
                original_body, sender_address, sender_hint, sender_handle,
                rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count, rx_route_hints,
                rx_source_authenticated, delivered_flooded, unknown_original,
                message_type, forward_secret, delivery_session_id, delivery_handle,
                delivery_progress_at_ms, regarding_wire_id)
            VALUES ('alice', '7', 3, 'peer', 1, 'body', 1234, 44, 4464,
                'acknowledged', 1, 3, 1, 1,
                'first', 'sender', x'010203', 'Ridge',
                -100, -5, 9, 4, x'AABBCC',
                0, 1, 1,
                1, 1, '8', 9,
                5555, 2)",
            [],
        )
        .unwrap();
    store
        .connection()
        .execute_batch(
            "INSERT INTO chat_delivery_fragment (owner_identity_id, session_id, handle,
                fragment_index, state, repeaters, anonymous_repeats)
            VALUES ('alice', '8', 9, 1, 'acknowledged', x'0A0B0C0D', 2),
                ('alice', '8', 9, 0, 'acknowledged', x'0C0D0E0F', 5),
                ('alice', '8', 9, 2, 'sent', NULL, 1);",
        )
        .unwrap();
    let row = transcript(&store, PEER).remove(0);
    let row_id = row.row_id;
    let mut repeaters = row.repeats.as_ref().unwrap().repeaters.clone();
    repeaters.sort();
    assert_eq!(repeaters, [[0x0A, 0x0B], [0x0C, 0x0D], [0x0E, 0x0F]]);
    assert_eq!(
        row,
        MobileStoredChatMessageRecord {
            reference: reference("7", 3),
            body: "body".into(),
            outbound: true,
            delivery_state: Some(MobileStoredChatDeliveryState::Acknowledged),
            is_deleted: false,
            created_at_ms: 1234,
            wire_id: Some(44),
            epoch: Some(4464),
            is_edited: true,
            presence: MobileChatPresence::GapIdle,
            received_late: true,
            delivered_late: true,
            original_body: Some("first".into()),
            sender_address: Some("sender".into()),
            sender_hint: Some(vec![1, 2, 3]),
            sender_handle: Some("Ridge".into()),
            reception: Some(MobileStoredChatReceptionRecord {
                rssi_dbm: Some(-100),
                snr_centibels: Some(-5),
                lqi: Some(9),
                hop_count: Some(4),
                // The odd byte out is dropped.
                route_hints: vec![vec![0xAA, 0xBB]],
                source_authenticated: false,
            }),
            row_id,
            delivered_flooded: true,
            reactions: vec![],
            is_reply: true,
            is_edit_of_unknown: true,
            is_status: true,
            is_forward_secret: true,
            reply_target: None,
            quote: Some(MobileStoredChatQuoteRecord { original: None }),
            repeats: Some(MobileStoredChatRepeatsRecord {
                repeaters: row.repeats.as_ref().unwrap().repeaters.clone(),
                anonymous: 5,
                progress_at_ms: 5555,
            }),
        }
    );
    // A presence code this store never writes reads as present.
    store
        .connection()
        .execute("UPDATE chat_message SET presence = 9", [])
        .unwrap();
    assert_eq!(
        transcript(&store, PEER)[0].presence,
        MobileChatPresence::Present
    );
}

/// A stored figure its field cannot hold reads as absent rather than
/// wrapped, and a reference whose handle no message can have names
/// nothing; the rest of the row still reads.
#[test]
fn a_value_out_of_its_field_s_range_reads_as_absent() {
    let (_directory, store) = open();
    apply(&store, vec![inbound(1, 0, PEER, 5, "odd")]);
    store
        .connection()
        .execute(
            "UPDATE chat_message SET wire_id = 300, epoch = 70000,
                rx_source_authenticated = 1, rx_rssi_dbm = -90, rx_snr_cb = 40000,
                rx_lqi = -1, rx_hop_count = 256,
                regarding_target_session_id = '1', regarding_target_handle = -1",
            [],
        )
        .unwrap();
    let row = message(&store, PEER, "odd");
    assert_eq!((row.wire_id, row.epoch), (None, None));
    let reception = row.reception.unwrap();
    assert_eq!(reception.rssi_dbm, Some(-90));
    assert_eq!(
        (reception.snr_centibels, reception.lqi, reception.hop_count),
        (None, None, None)
    );
    assert_eq!(row.reply_target, None);
}
