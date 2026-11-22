//! The chat commands, the `EMERGENCY` interlock and the share link, over a
//! running core whose radio is a state the tests set: nothing carries its
//! frames, so the pipeline fails each as it comes.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::chat::{REVISE_WINDOW_MS, reaction_body, reaction_from_body};
use super::test_support::{Core, NOW_MS, identity};
use super::worker::TestHooks;
use super::{
    MobileAppChangesRecord, MobileAppChatRequest, MobileAppError, MobileAppResent,
    MobileAppStartFailure, MobilePositionRecord, MobileReaction, Options,
};
use crate::mobile_chat::MobileChatPresence;
use crate::radio_driver::{MobileRadioPhase, MobileRadioStateRecord};
use crate::store::{
    MobileStoredChatDeliveryState, MobileStoredChatMessageRecord, MobileStoredChatMessageRefRecord,
};
use crate::ulcp::UlcpHostOwnership;

/// The phone's identity secret.
const PHONE: u8 = 0x51;

fn address_of(seed: u8) -> String {
    identity(seed).public_identity().canonical_address
}

/// The conversation address a name's channel is kept under.
fn named_address(name: &str) -> String {
    let key = crate::inspect_channel_name(name.to_owned()).unwrap().key;
    crate::channel_conversation_address(key).unwrap()
}

/// `EMERGENCY`'s conversation, opened.
async fn emergency(core: &Core, owner: &str) -> String {
    let id = core
        .store
        .channels(owner.to_owned())
        .unwrap()
        .into_iter()
        .find(|channel| channel.canonical_name.as_deref() == Some("emergency"))
        .unwrap()
        .id;
    // Through the store, which needs no key.
    let address = named_address("emergency");
    core.store
        .ensure_channel_conversation(owner.to_owned(), id, address.clone(), NOW_MS)
        .unwrap();
    address
}

/// A running core, its owner, and a peer it has a conversation with.
async fn running_with(options: Options) -> (Core, String, String) {
    let core = Core::with_options(options);
    let owner = core.start(PHONE).await.canonical_address;
    let peer = core
        .core
        .save_peer(address_of(0x61), None, true)
        .await
        .unwrap();
    core.core.poll_changes();
    (core, owner, peer)
}

async fn running() -> (Core, String, String) {
    running_with(Options::default()).await
}

/// A core whose test hooks the test holds.
fn hooked() -> (Options, Arc<TestHooks>) {
    let hooks = Arc::new(TestHooks::default());
    let options = Options {
        hooks: hooks.clone(),
        ..Options::default()
    };
    (options, hooks)
}

/// Report a radio attached, held by `host`.
async fn radio(core: &Core, host: Option<UlcpHostOwnership>) {
    core.core
        .on_worker(move |worker| async move {
            worker.shared.publish(|snapshot| {
                snapshot.radio = host.map(|host| MobileRadioStateRecord {
                    phase: MobileRadioPhase::Attached,
                    host,
                    ..MobileRadioStateRecord::idle()
                });
                MobileAppChangesRecord::default()
            });
            Ok(())
        })
        .await
        .unwrap();
}

async fn attached(core: &Core) {
    radio(core, Some(UlcpHostOwnership::Ours)).await;
}

/// The chat store's faults, for the running session.
async fn faults(core: &Core) -> Arc<crate::mobile_mesh::ChatStoreFaults> {
    core.session().await.unwrap().chat_faults().unwrap()
}

/// A row as the chat store would have written it.
#[derive(Clone)]
struct Row {
    session_id: &'static str,
    handle: u32,
    outbound: bool,
    body: &'static str,
    created_at_ms: i64,
    delivery_state: Option<&'static str>,
    wire_id: Option<u8>,
    epoch: Option<u16>,
    presence: i64,
}

impl Default for Row {
    fn default() -> Self {
        Self {
            session_id: "7",
            handle: 1,
            outbound: true,
            body: "Trailhead at noon",
            created_at_ms: NOW_MS - 60_000,
            delivery_state: Some("failed"),
            wire_id: Some(9),
            epoch: Some(0),
            presence: 0,
        }
    }
}

impl Row {
    fn reference(&self) -> MobileStoredChatMessageRefRecord {
        MobileStoredChatMessageRefRecord {
            session_id: self.session_id.to_owned(),
            handle: self.handle,
        }
    }

    fn insert(&self, core: &Core, owner: &str, address: &str) -> MobileStoredChatMessageRefRecord {
        rusqlite::Connection::open(core.directory.path().join("app.sqlite"))
            .unwrap()
            .execute(
                "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                    conversation_address, direction, body, created_at_ms,
                    delivery_state, wire_id, epoch, presence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    owner,
                    self.session_id,
                    self.handle,
                    address,
                    i64::from(self.outbound),
                    self.body,
                    self.created_at_ms,
                    self.delivery_state,
                    self.wire_id,
                    self.epoch,
                    self.presence,
                ],
            )
            .unwrap();
        self.reference()
    }
}

fn stored(
    core: &Core,
    owner: &str,
    address: &str,
    message: &MobileStoredChatMessageRefRecord,
) -> Option<MobileStoredChatMessageRecord> {
    core.store.chat_message(owner, address, message).unwrap()
}

fn messages(core: &Core, owner: &str, address: &str) -> Vec<MobileStoredChatMessageRecord> {
    core.store
        .chat_message_page_newest(owner.to_owned(), address.to_owned(), 50)
        .unwrap()
        .messages
}

fn draft(core: &Core, owner: &str, address: &str) -> String {
    core.store.draft(owner, address).unwrap().unwrap()
}

fn typed(text: &str) -> MobileAppChatRequest {
    MobileAppChatRequest::Typed {
        text: text.to_owned(),
        forward_secret: None,
    }
}

/// Wait, in real time, until `done` holds.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// --- Sending and the draft. ---

#[tokio::test]
async fn a_sent_message_replaces_a_stale_draft_and_clears_it() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    // The debounce saved only a prefix before the tap.
    core.core
        .save_draft(peer.clone(), "Trail".into())
        .await
        .unwrap();
    core.core.poll_changes();
    core.core
        .send_chat(
            peer.clone(),
            typed(" Trailhead "),
            Some(" Trailhead ".into()),
        )
        .await
        .unwrap();
    assert_eq!(draft(&core, &owner, &peer), "");
    let changes = core.core.poll_changes();
    assert!(changes.conversations_changed);
    assert!(changes.transcripts.contains(&peer));
    let sent = messages(&core, &owner, &peer);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].outbound);
    assert_eq!(sent[0].body, "Trailhead", "trimmed");
}

#[tokio::test]
async fn words_saved_during_a_send_stay() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let (sent, saved) = tokio::join!(
        core.core
            .send_chat(peer.clone(), typed("hello"), Some("hello".into())),
        core.core.save_draft(peer.clone(), "and more".into()),
    );
    sent.unwrap();
    saved.unwrap();
    assert_eq!(draft(&core, &owner, &peer), "and more");
}

#[tokio::test]
async fn without_a_submitted_draft_the_draft_is_left() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    core.core
        .save_draft(peer.clone(), "unrelated".into())
        .await
        .unwrap();
    core.core
        .send_chat(peer.clone(), typed("hi"), None)
        .await
        .unwrap();
    assert_eq!(draft(&core, &owner, &peer), "unrelated");
}

#[tokio::test]
async fn a_refused_send_keeps_the_submitted_words() {
    let (core, owner, peer) = running().await;
    assert_eq!(
        core.core
            .send_chat(peer.clone(), typed("hello"), Some("hello ".into()))
            .await,
        Err(MobileAppError::NoRadio)
    );
    assert_eq!(draft(&core, &owner, &peer), "hello ", "as typed");
    assert!(core.core.poll_changes().conversations_changed);
    let emergency = emergency(&core, &owner).await;
    assert_eq!(
        core.core
            .send_chat(emergency.clone(), typed("help"), Some("help".into()))
            .await,
        Err(MobileAppError::EmergencyNotCertified)
    );
    assert_eq!(draft(&core, &owner, &emergency), "help");
    assert!(messages(&core, &owner, &peer).is_empty());
}

#[tokio::test]
async fn a_message_not_saved_keeps_its_draft() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    faults(&core)
        .await
        .refuse_commit
        .store(true, Ordering::Relaxed);
    assert!(matches!(
        core.core
            .send_chat(peer.clone(), typed("hello"), Some("hello".into()))
            .await,
        Err(MobileAppError::Store { .. })
    ));
    assert_eq!(draft(&core, &owner, &peer), "hello");
    assert!(messages(&core, &owner, &peer).is_empty());
}

#[tokio::test]
async fn a_message_kept_but_not_queued_clears_its_draft_and_says_so() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    faults(&core)
        .await
        .refuse_release
        .store(true, Ordering::Relaxed);
    core.core.poll_changes();
    assert_eq!(
        core.core
            .send_chat(peer.clone(), typed("hello"), Some("hello".into()))
            .await,
        Err(MobileAppError::MessageNotQueued { recorded: true })
    );
    assert_eq!(draft(&core, &owner, &peer), "");
    assert!(core.core.poll_changes().transcripts.contains(&peer));
    let kept = messages(&core, &owner, &peer);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept[0].delivery_state,
        Some(MobileStoredChatDeliveryState::Undelivered)
    );
}

#[tokio::test]
async fn a_failed_draft_clear_does_not_fail_the_send() {
    let (options, hooks) = hooked();
    let (core, owner, peer) = running_with(options).await;
    attached(&core).await;
    hooks.fail_draft_clear.store(true, Ordering::Relaxed);
    core.core
        .send_chat(peer.clone(), typed("hello"), Some("hello".into()))
        .await
        .unwrap();
    assert_eq!(draft(&core, &owner, &peer), "hello");
    assert_eq!(messages(&core, &owner, &peer).len(), 1);
}

#[tokio::test]
async fn a_send_whose_caller_stopped_waiting_still_lands() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let send = core
        .core
        .send_chat(peer.clone(), typed("hello"), Some("hello".into()));
    // Polled once, so the job is on its way, then dropped.
    tokio::select! {
        biased;
        _ = send => panic!("answered at once"),
        () = std::future::ready(()) => {}
    }
    until("the message is kept", || {
        messages(&core, &owner, &peer).len() == 1
    })
    .await;
    until("the draft is cleared", || {
        draft(&core, &owner, &peer).is_empty()
    })
    .await;
}

#[tokio::test]
async fn a_send_whose_counters_were_not_saved_counts_as_sent() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    faults(&core)
        .await
        .counters_unsaved
        .store(true, Ordering::Relaxed);
    core.core
        .send_chat(peer.clone(), typed("hello"), Some("hello".into()))
        .await
        .unwrap();
    assert_eq!(draft(&core, &owner, &peer), "");
    let sent = messages(&core, &owner, &peer);
    assert_eq!(sent.len(), 1);
    assert_ne!(
        sent[0].delivery_state,
        Some(MobileStoredChatDeliveryState::Undelivered),
        "not recorded as never sent"
    );
}

#[tokio::test]
async fn a_draft_only_rides_what_the_composer_submits() {
    let (core, _, peer) = running().await;
    let message = Row::default().reference();
    assert_eq!(
        core.core
            .send_chat(
                peer.clone(),
                MobileAppChatRequest::Delete { message },
                Some("x".into())
            )
            .await,
        Err(MobileAppError::InvalidRequest)
    );
    assert_eq!(
        core.core.send_chat(peer, typed("   "), None).await,
        Err(MobileAppError::InvalidRequest)
    );
}

// --- The store commands. ---

#[tokio::test]
async fn drafts_are_kept_by_address_for_both_kinds() {
    let (core, owner, peer) = running().await;
    let public = named_address("public");
    for address in [&peer, &public] {
        core.core
            .save_draft(address.clone(), "first".into())
            .await
            .unwrap();
        assert!(core.core.poll_changes().conversations_changed);
        // The same text again changes nothing.
        core.core
            .save_draft(address.clone(), "first".into())
            .await
            .unwrap();
        assert!(!core.core.poll_changes().conversations_changed);
        core.core
            .append_draft(address.clone(), "second".into())
            .await
            .unwrap();
        assert_eq!(draft(&core, &owner, address), "first\nsecond");
        core.core
            .save_draft(address.clone(), String::new())
            .await
            .unwrap();
        core.core
            .append_draft(address.clone(), "whole".into())
            .await
            .unwrap();
        assert_eq!(draft(&core, &owner, address), "whole");
    }
    assert_eq!(
        core.core.save_draft(address_of(0x62), "x".into()).await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core
            .save_draft(named_address("not joined"), "x".into())
            .await,
        Err(MobileAppError::NotFound)
    );
}

#[tokio::test]
async fn mark_read_raises_only_when_something_was_unread() {
    let (core, owner, peer) = running().await;
    for (handle, created_at_ms) in [(1, NOW_MS - 3_000), (2, NOW_MS - 1_000)] {
        Row {
            handle,
            outbound: false,
            delivery_state: None,
            created_at_ms,
            ..Row::default()
        }
        .insert(&core, &owner, &peer);
    }
    let unread = |core: &Core| {
        core.core
            .state(true)
            .unwrap()
            .direct_conversations
            .into_iter()
            .find(|conversation| conversation.peer.stored.public_address == peer)
            .unwrap()
            .unread_count
    };
    assert_eq!(unread(&core), 2);
    // Through the first only: the second stays unread.
    core.core
        .mark_read(peer.clone(), Some(NOW_MS - 2_000))
        .await
        .unwrap();
    assert!(core.core.poll_changes().conversations_changed);
    assert_eq!(unread(&core), 1);
    // A bound behind the read time never moves it back.
    core.core
        .mark_read(peer.clone(), Some(NOW_MS - 10_000))
        .await
        .unwrap();
    assert!(!core.core.poll_changes().conversations_changed);
    assert_eq!(unread(&core), 1);
    core.core.mark_read(peer.clone(), None).await.unwrap();
    assert!(core.core.poll_changes().conversations_changed);
    assert_eq!(unread(&core), 0);
    // A thread that marks itself read on every change cannot loop.
    core.clock.advance(1_000);
    core.core.mark_read(peer.clone(), None).await.unwrap();
    assert!(!core.core.poll_changes().conversations_changed);
    // Nothing stored there is not an error.
    core.core.mark_read(address_of(0x62), None).await.unwrap();
}

#[tokio::test]
async fn clearing_and_generating_raise_the_transcript() {
    let (core, owner, peer) = running().await;
    core.core
        .save_draft(peer.clone(), "kept".into())
        .await
        .unwrap();
    core.core.generate_messages(peer.clone(), 5).await.unwrap();
    let changes = core.core.poll_changes();
    assert!(changes.transcripts.contains(&peer) && changes.conversations_changed);
    assert_eq!(messages(&core, &owner, &peer).len(), 5);
    core.core.clear_messages(peer.clone()).await.unwrap();
    assert!(core.core.poll_changes().transcripts.contains(&peer));
    assert!(messages(&core, &owner, &peer).is_empty());
    assert_eq!(draft(&core, &owner, &peer), "kept");
}

#[tokio::test]
async fn store_commands_are_kept_while_a_start_failed() {
    let core = Core::new();
    let owner = address_of(PHONE);
    let peer = address_of(0x61);
    core.store
        .upsert_identity(owner.clone(), owner.clone(), 1)
        .unwrap();
    core.store
        .upsert_peer(
            owner.clone(),
            peer.clone(),
            crate::store::MobilePeerUpsertRecord {
                is_saved: true,
                ..crate::store::MobilePeerUpsertRecord::default()
            },
        )
        .unwrap();
    core.store
        .ensure_direct_conversation(owner.clone(), peer.clone(), 1)
        .unwrap();
    // Idle, before any start.
    assert_eq!(
        core.core.save_draft(peer.clone(), "x".into()).await,
        Err(MobileAppError::NoOwner)
    );
    core.core.set_owner(Some(owner.clone())).unwrap();
    core.core
        .save_draft(peer.clone(), "idle".into())
        .await
        .unwrap();
    assert_eq!(draft(&core, &owner, &peer), "idle");
    // Failed.
    std::fs::write(core.counter_directory(), b"in the way").unwrap();
    assert_eq!(
        core.core.start(identity(PHONE)).await,
        Err(MobileAppError::StartFailed {
            reason: MobileAppStartFailure::Session
        })
    );
    core.core
        .append_draft(peer.clone(), "failed".into())
        .await
        .unwrap();
    assert_eq!(draft(&core, &owner, &peer), "idle\nfailed");
    core.core.mark_read(peer.clone(), None).await.unwrap();
    core.core.generate_messages(peer.clone(), 2).await.unwrap();
    core.core.clear_messages(peer.clone()).await.unwrap();
    // A send's words are kept; nothing is sent.
    assert_eq!(
        core.core
            .send_chat(peer.clone(), typed("later"), Some("later".into()))
            .await,
        Err(MobileAppError::NotRunning)
    );
    assert_eq!(draft(&core, &owner, &peer), "later");
    assert_eq!(
        core.core
            .resend(peer.clone(), Row::default().reference(), false)
            .await,
        Err(MobileAppError::NotRunning)
    );
    assert_eq!(
        core.core.request_missing(peer, Vec::new()).await,
        Err(MobileAppError::NotRunning)
    );
}

// --- The interlock. ---

/// Every command the interlock gates, on `address`.
async fn gated(core: &Core, address: &str) -> Vec<Result<(), MobileAppError>> {
    let message = Row::default().reference();
    let mut answers = Vec::new();
    for request in [
        typed("help"),
        MobileAppChatRequest::Reply {
            target: message.clone(),
            text: "here".into(),
            forward_secret: None,
        },
        MobileAppChatRequest::Edit {
            message: message.clone(),
            text: "help!".into(),
        },
        MobileAppChatRequest::Delete {
            message: message.clone(),
        },
        MobileAppChatRequest::React {
            message: message.clone(),
            reaction: Some(MobileReaction::Heart),
        },
    ] {
        answers.push(core.core.send_chat(address.to_owned(), request, None).await);
    }
    answers.push(
        core.core
            .resend(address.to_owned(), message.clone(), false)
            .await
            .map(|_| ()),
    );
    answers.push(
        core.core
            .request_missing(address.to_owned(), vec![message])
            .await,
    );
    answers.push(
        core.core
            .request_member_identity(address.to_owned(), vec![1, 2, 3])
            .await,
    );
    answers
}

#[tokio::test]
async fn emergency_refuses_before_its_warning_and_before_the_radio() {
    let (core, owner, _) = running().await;
    let emergency = emergency(&core, &owner).await;
    // A failed message of ours there, for the resend to find.
    Row::default().insert(&core, &owner, &emergency);
    for answer in gated(&core, &emergency).await {
        assert_eq!(answer, Err(MobileAppError::EmergencyNotCertified));
    }
    // Public is never gated.
    for answer in gated(&core, &named_address("public")).await {
        assert_ne!(answer, Err(MobileAppError::EmergencyNotCertified));
    }
    core.core.poll_changes();
    core.core.certify_emergency().unwrap();
    assert_eq!(core.core.poll_changes().emergency_certified, Some(true));
    assert!(core.core.status().unwrap().emergency_certified);
    // Again raises nothing.
    core.core.certify_emergency().unwrap();
    assert_eq!(core.core.poll_changes().emergency_certified, None);
    for answer in gated(&core, &emergency).await {
        assert_eq!(answer, Err(MobileAppError::NoRadio));
    }
}

#[tokio::test]
async fn emergency_is_known_by_its_row_while_the_vault_is_locked() {
    let core = Core::new();
    core.vault.set_locked(true);
    let owner = core.start(PHONE).await.canonical_address;
    attached(&core).await;
    let emergency = emergency(&core, &owner).await;
    Row::default().insert(&core, &owner, &emergency);
    for answer in gated(&core, &emergency).await {
        assert_eq!(answer, Err(MobileAppError::EmergencyNotCertified));
    }
    core.core.certify_emergency().unwrap();
    // Past the gate, the locked key answers.
    assert_eq!(
        core.core.send_chat(emergency, typed("help"), None).await,
        Err(MobileAppError::Vault {
            error: crate::SecretVaultError::Unavailable
        })
    );
}

#[tokio::test]
async fn a_certification_is_in_effect_for_the_next_send() {
    let (core, owner, _) = running().await;
    attached(&core).await;
    let emergency = emergency(&core, &owner).await;
    core.core.certify_emergency().unwrap();
    core.core
        .send_chat(emergency.clone(), typed("TEST: radio check"), None)
        .await
        .unwrap();
    assert_eq!(messages(&core, &owner, &emergency).len(), 1);
}

#[tokio::test]
async fn a_certification_lasts_until_the_owner_changes() {
    let (core, _, _) = running().await;
    core.core.certify_emergency().unwrap();
    // Radios come and go under it.
    core.core.use_radio(None).await.unwrap();
    assert!(core.core.status().unwrap().emergency_certified);
    core.core.poll_changes();
    core.core.erase(false).await.unwrap();
    assert!(!core.core.status().unwrap().emergency_certified);
    assert_eq!(core.core.poll_changes().emergency_certified, Some(false));
    assert_eq!(core.core.certify_emergency(), Err(MobileAppError::NoOwner));
}

#[tokio::test]
async fn a_start_under_another_identity_after_a_failed_one_is_uncertified() {
    let core = Core::new();
    std::fs::write(core.counter_directory(), b"in the way").unwrap();
    assert!(core.core.start(identity(PHONE)).await.is_err());
    core.core.certify_emergency().unwrap();
    std::fs::remove_file(core.counter_directory()).unwrap();
    core.start(PHONE + 1).await;
    assert!(!core.core.status().unwrap().emergency_certified);
}

// --- The rules from the row. ---

#[tokio::test]
async fn what_a_row_allows() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let send = |request| core.core.send_chat(peer.clone(), request, None);
    let old = Row {
        handle: 1,
        created_at_ms: NOW_MS - REVISE_WINDOW_MS - 1,
        delivery_state: Some("acknowledged"),
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    let inbound = Row {
        handle: 2,
        outbound: false,
        delivery_state: None,
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    let failed = Row {
        handle: 3,
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    let edit = |message| MobileAppChatRequest::Edit {
        message,
        text: "new words".into(),
    };
    for (request, why) in [
        (edit(old.clone()), "past the window"),
        (edit(inbound.clone()), "not ours"),
        (
            MobileAppChatRequest::Delete {
                message: inbound.clone(),
            },
            "not ours",
        ),
        (
            MobileAppChatRequest::React {
                message: failed.clone(),
                reaction: Some(MobileReaction::ThumbsUp),
            },
            "never delivered",
        ),
    ] {
        assert_eq!(
            send(request).await,
            Err(MobileAppError::InvalidRequest),
            "{why}"
        );
    }
    assert_eq!(
        core.core.resend(peer.clone(), old.clone(), false).await,
        Err(MobileAppError::InvalidRequest),
        "delivered"
    );
    // Another conversation's row is not this one's.
    let public = named_address("public");
    assert_eq!(
        core.core
            .send_chat(
                public.clone(),
                MobileAppChatRequest::Delete { message: failed },
                None
            )
            .await,
        Err(MobileAppError::NotFound)
    );
    assert_eq!(
        core.core.resend(public, old, false).await,
        Err(MobileAppError::NotFound)
    );
}

#[tokio::test]
async fn a_row_another_session_wrote_is_named_by_its_wire_fields() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let staged = Row {
        session_id: "staging-direct",
        handle: 1,
        outbound: false,
        delivery_state: None,
        wire_id: None,
        epoch: None,
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    // Nothing names it: no reaction can go.
    assert_eq!(
        core.core
            .send_chat(
                peer.clone(),
                MobileAppChatRequest::React {
                    message: staged.clone(),
                    reaction: Some(MobileReaction::Heart),
                },
                None
            )
            .await,
        Err(MobileAppError::InvalidRequest)
    );
    // A reply still goes, as what was written.
    core.core
        .send_chat(
            peer.clone(),
            MobileAppChatRequest::Reply {
                target: staged,
                text: "On my way".into(),
                forward_secret: None,
            },
            None,
        )
        .await
        .unwrap();
    // So does one whose target is gone.
    core.core
        .send_chat(
            peer.clone(),
            MobileAppChatRequest::Reply {
                target: Row {
                    session_id: "9",
                    handle: 99,
                    ..Row::default()
                }
                .reference(),
                text: "Still coming".into(),
                forward_secret: None,
            },
            None,
        )
        .await
        .unwrap();
    let sent: Vec<_> = messages(&core, &owner, &peer)
        .into_iter()
        .filter(|message| message.outbound)
        .map(|message| (message.body, message.is_reply))
        .collect();
    assert_eq!(
        sent,
        [
            ("On my way".to_owned(), false),
            ("Still coming".to_owned(), false)
        ]
    );
}

// --- Resending and repair. ---

#[tokio::test]
async fn a_resend_that_cannot_go_in_place_goes_as_new_and_replaces_the_failed_row() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    // No wire ID, past the window, and frames the stream cannot take.
    let no_wire = Row {
        handle: 1,
        wire_id: None,
        body: "first",
        ..Row::default()
    };
    let too_old = Row {
        handle: 2,
        created_at_ms: NOW_MS - REVISE_WINDOW_MS - 1,
        body: "second",
        ..Row::default()
    };
    let moved_on = Row {
        handle: 3,
        wire_id: Some(5),
        body: "third",
        ..Row::default()
    };
    rusqlite::Connection::open(core.directory.path().join("app.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO chat_outbound_archive (owner_identity_id, conversation_address,
                message_id, fragment_index, payload)
            VALUES (?, ?, 5, -1, x'00')",
            rusqlite::params![owner, peer],
        )
        .unwrap();
    for row in [no_wire, too_old, moved_on] {
        let reference = row.insert(&core, &owner, &peer);
        core.core.poll_changes();
        assert_eq!(
            core.core
                .resend(peer.clone(), reference.clone(), false)
                .await,
            Ok(MobileAppResent::AsNew),
            "{}",
            row.body
        );
        assert!(core.core.poll_changes().transcripts.contains(&peer));
        assert_eq!(
            stored(&core, &owner, &peer, &reference),
            None,
            "{}",
            row.body
        );
        assert!(
            messages(&core, &owner, &peer)
                .iter()
                .any(|message| message.body == row.body && message.reference != reference)
        );
    }
}

#[tokio::test]
async fn a_row_resent_twice_at_once_goes_once() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let failed = Row {
        wire_id: None,
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    let (first, second) = tokio::join!(
        core.core.resend(peer.clone(), failed.clone(), false),
        core.core.resend(peer.clone(), failed.clone(), false),
    );
    assert_eq!(first, Ok(MobileAppResent::AsNew));
    assert_eq!(second, Err(MobileAppError::InvalidRequest));
    assert_eq!(stored(&core, &owner, &peer, &failed), None);
    assert_eq!(messages(&core, &owner, &peer).len(), 1);
    // Once it has run, the row is no longer there to resend.
    assert_eq!(
        core.core.resend(peer.clone(), failed, false).await,
        Err(MobileAppError::NotFound)
    );
}

#[tokio::test]
async fn a_resend_kept_but_not_queued_leaves_one_failed_row() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let failed = Row {
        wire_id: None,
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    faults(&core)
        .await
        .refuse_release
        .store(true, Ordering::Relaxed);
    assert_eq!(
        core.core.resend(peer.clone(), failed.clone(), false).await,
        Err(MobileAppError::MessageNotQueued { recorded: true })
    );
    assert_eq!(stored(&core, &owner, &peer, &failed), None);
    assert_eq!(messages(&core, &owner, &peer).len(), 1);
}

#[tokio::test]
async fn missing_messages_no_session_holds_resolve_unavailable() {
    let (core, owner, peer) = running().await;
    attached(&core).await;
    let gap = |session_id, handle| Row {
        session_id,
        handle,
        outbound: false,
        delivery_state: None,
        presence: 3,
        ..Row::default()
    };
    // A staged gap, and one from an earlier session.
    let staged = gap("staging-direct", 1).insert(&core, &owner, &peer);
    let earlier = gap("8", 2).insert(&core, &owner, &peer);
    // Another conversation's gap is passed over.
    let public = named_address("public");
    let elsewhere = gap("8", 3).insert(&core, &owner, &public);
    core.core.poll_changes();
    core.core
        .request_missing(
            peer.clone(),
            vec![staged.clone(), earlier.clone(), elsewhere.clone()],
        )
        .await
        .unwrap();
    assert!(core.core.poll_changes().transcripts.contains(&peer));
    for reference in [staged, earlier] {
        assert_eq!(
            stored(&core, &owner, &peer, &reference).unwrap().presence,
            MobileChatPresence::Unavailable
        );
    }
    assert_eq!(
        stored(&core, &owner, &public, &elsewhere).unwrap().presence,
        MobileChatPresence::GapIdle
    );
}

// --- The radio guard. ---

#[tokio::test]
async fn transmitting_needs_this_phone_s_radio() {
    let (core, owner, peer) = running().await;
    let failed = Row::default().insert(&core, &owner, &peer);
    for (host, refusal) in [
        (None, MobileAppError::NoRadio),
        (
            Some(UlcpHostOwnership::OtherHost),
            MobileAppError::NotThisPhone,
        ),
    ] {
        radio(&core, host).await;
        assert_eq!(
            core.core.send_chat(peer.clone(), typed("hi"), None).await,
            Err(refusal.clone())
        );
        assert_eq!(
            core.core.resend(peer.clone(), failed.clone(), false).await,
            Err(refusal.clone())
        );
        assert_eq!(
            core.core.request_missing(peer.clone(), Vec::new()).await,
            Err(refusal.clone())
        );
        assert_eq!(core.core.advertise_identity().await, Err(refusal.clone()));
        assert!(!super::radio_carries_this_phone(
            core.core.status().unwrap().radio
        ));
    }
    attached(&core).await;
    assert!(super::radio_carries_this_phone(
        core.core.status().unwrap().radio
    ));
    core.core.advertise_identity().await.unwrap();
}

// --- The share link. ---

#[tokio::test]
async fn the_share_link_is_signed_with_the_stored_name_and_no_location() {
    let core = Core::new();
    assert_eq!(
        core.core.identity_share_uri().await,
        Err(MobileAppError::NotRunning)
    );
    let owner = core.start(PHONE).await.canonical_address;
    core.core
        .set_advertised_name("Ridge Camp".into())
        .await
        .unwrap();
    core.core
        .set_policy(super::MobileAppPolicyRecord {
            advert_interval_seconds: 0,
            beacon_interval_seconds: 0,
            discoverable: true,
            flood_hops: 1,
            beacon_flood_hops: 0,
            location_precision: Some(4),
            test_message_alerts: false,
        })
        .await
        .unwrap();
    core.core
        .set_location(Some(MobilePositionRecord {
            latitude_degrees: 46.85,
            longitude_degrees: -121.76,
            accuracy_meters: Some(5.0),
        }))
        .await
        .unwrap();
    let link = crate::inspect_node_uri(core.core.identity_share_uri().await.unwrap()).unwrap();
    assert_eq!(link.canonical_address, owner);
    let identity = link.identity.unwrap();
    assert_eq!(identity.signature, crate::IdentitySignatureState::Valid);
    assert_eq!(identity.name.as_deref(), Some("Ridge Camp"));
    assert_eq!(identity.timestamp, Some((NOW_MS / 1000) as u32));
    assert_eq!((identity.latitude, identity.longitude), (None, None));
}

// --- Reactions. ---

#[test]
fn every_spelling_ios_read_reads_as_the_same_emote() {
    use MobileReaction::{Exclaim, Heart, Laugh, Question, ThumbsDown, ThumbsUp};
    for (body, reaction) in [
        ("<3", Heart),
        ("\u{2665}", Heart),
        ("\u{2665}\u{fe0e}", Heart),
        ("\u{2764}", Heart),
        ("\u{2764}\u{fe0f}", Heart),
        ("\u{1fa77}", Heart),
        ("+1", ThumbsUp),
        ("\u{1f44d}", ThumbsUp),
        ("\u{1f44d}\u{1f3fb}", ThumbsUp),
        ("\u{1f44d}\u{1f3fc}", ThumbsUp),
        ("\u{1f44d}\u{1f3fd}", ThumbsUp),
        ("\u{1f44d}\u{1f3fe}", ThumbsUp),
        ("\u{1f44d}\u{1f3ff}", ThumbsUp),
        ("-1", ThumbsDown),
        ("\u{1f44e}", ThumbsDown),
        ("\u{1f44e}\u{1f3fd}", ThumbsDown),
        ("ha", Laugh),
        ("haha", Laugh),
        ("hahaha", Laugh),
        ("LOL", Laugh),
        ("lmao", Laugh),
        ("\u{1f923}", Laugh),
        ("!", Exclaim),
        ("!!", Exclaim),
        ("\u{2757}", Exclaim),
        ("\u{2755}", Exclaim),
        ("\u{203c}\u{fe0f}", Exclaim),
        ("?", Question),
        ("??", Question),
        ("\u{2753}", Question),
        ("\u{2754}", Question),
        (" ? ", Question),
    ] {
        assert_eq!(reaction_from_body(body), Some(reaction.clone()), "{body:?}");
    }
    // Anything else is its first cluster, whole however long.
    let family = "\u{1f468}\u{1f3fb}\u{200d}\u{1f469}\u{1f3fb}\u{200d}\u{1f467}\u{1f3fb}\u{200d}\u{1f466}\u{1f3fb}";
    for (body, cluster) in [
        ("\u{1f525} nice", "\u{1f525}"),
        ("nice", "n"),
        (family, family),
    ] {
        assert_eq!(
            reaction_from_body(body),
            Some(MobileReaction::Other {
                cluster: cluster.to_owned()
            })
        );
    }
    assert_eq!(reaction_from_body(""), None);
    assert_eq!(reaction_from_body("  "), None);
}

#[test]
fn a_reaction_goes_as_its_token() {
    assert_eq!(reaction_body(&MobileReaction::Heart).as_deref(), Some("<3"));
    for (cluster, body) in [
        ("\u{2764}\u{fe0f}", Some("<3")),
        ("\u{1f525}\u{1f525}", Some("\u{1f525}")),
        ("", None),
    ] {
        assert_eq!(
            reaction_body(&MobileReaction::Other {
                cluster: cluster.to_owned()
            })
            .as_deref(),
            body
        );
    }
}

#[tokio::test]
async fn transcript_messages_carry_their_reactions_and_revise_window() {
    let (core, owner, peer) = running().await;
    let ours = Row {
        delivery_state: Some("acknowledged"),
        ..Row::default()
    };
    let reference = ours.insert(&core, &owner, &peer);
    Row {
        handle: 2,
        outbound: false,
        delivery_state: None,
        ..Row::default()
    }
    .insert(&core, &owner, &peer);
    rusqlite::Connection::open(core.directory.path().join("app.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO chat_message (owner_identity_id, session_id, handle,
                conversation_address, direction, body, created_at_ms, is_reaction,
                regarding_target_session_id, regarding_target_handle, sender_address)
            VALUES (?, '7', 10, ?, 0, '\u{2764}\u{fe0f}', ?, 1, ?, ?, ?)",
            rusqlite::params![
                owner,
                peer,
                NOW_MS,
                reference.session_id,
                reference.handle,
                peer
            ],
        )
        .unwrap();
    let page = core.core.transcript_newest(peer.clone(), 10).unwrap();
    let ours = page
        .messages
        .iter()
        .find(|message| message.stored.reference == reference)
        .unwrap();
    assert_eq!(ours.reactions, [Some(MobileReaction::Heart)]);
    assert_eq!(ours.stored.reactions.len(), 1);
    assert_eq!(
        ours.revise_until_ms,
        Some(ours.stored.created_at_ms + REVISE_WINDOW_MS)
    );
    let theirs = page
        .messages
        .iter()
        .find(|message| !message.stored.outbound)
        .unwrap();
    assert_eq!(theirs.revise_until_ms, None);
}

// --- Links to a well-known channel's key. ---

#[test]
fn a_key_link_to_emergency_reads_as_emergency() {
    let emergency = crate::inspect_channel_name("EMERGENCY".into()).unwrap();
    let link =
        crate::format_channel_invitation(emergency.key.clone(), None, None, None, None).unwrap();
    let preview = crate::inspect_channel_uri(link).unwrap();
    assert_eq!(preview.kind, crate::ChannelKindRecord::NamedPublic);
    assert_eq!(preview.canonical_name.as_deref(), Some("emergency"));
    assert_eq!(preview.key, emergency.key);
    let other = crate::format_channel_invitation(vec![7; 32], None, None, None, None).unwrap();
    assert_eq!(
        crate::inspect_channel_uri(other).unwrap().kind,
        crate::ChannelKindRecord::PrivateKey
    );
}
