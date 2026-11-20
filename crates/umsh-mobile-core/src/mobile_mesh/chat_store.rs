//! A session's chat, kept in the application store.
//!
//! With a store attached, the session stores its own chat effects as they
//! come: each batch in one transaction, on a thread of its own so the
//! worker never waits on the disk. The platform hears only what changed.
//! A send is made durable before anything goes on the air, and runs to the
//! end on that thread whatever becomes of the caller.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, oneshot};

use super::{ChatComposeRequest, MobileChatWorkerEvent, MobileMeshError, MobileMeshSession};
use crate::mobile_chat::{
    MobileChatArchiveResultKind, MobileChatOriginalRef, MobileChatRegardingRef,
};
use crate::store::{
    ChatBatchContext, ChatBatchEffects, MobileAppStore, MobileChatChangesRecord, MobileStoreError,
};

/// How long a batch that could not be stored waits before it is tried
/// again.
pub(super) const RETRY_DELAY: Duration = Duration::from_secs(2);

/// How many times a batch is tried before it is given up. Holding one
/// that cannot be stored would hold every batch behind it, and that is the
/// worse of the two.
const ATTEMPT_LIMIT: u32 = 3;

/// A message to send, as the user asked for it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileChatSendRequest {
    /// Text as the user typed it into a conversation: a `/me ` prefix
    /// makes it status text. To a peer it goes under a session with
    /// forward secrecy, or never under one, as `forward_secret` says the
    /// composer showed it; without, under one only when one is held.
    Typed {
        text: String,
        forward_secret: Option<bool>,
    },
    /// Status text, its body taken as it stands.
    Status { body: String },
    /// A message, its body taken as it stands.
    Text { body: String },
    /// A failed message's words as a new message, as the user chose.
    Again {
        body: String,
        status: bool,
        forward_secret: bool,
    },
    /// An edit of a message of ours.
    Edit {
        original: MobileChatOriginalRef,
        body: String,
    },
    /// A message of ours taken back.
    Delete { original: MobileChatOriginalRef },
    /// A reaction to either party's message; an empty body withdraws it.
    Reaction {
        target: MobileChatRegardingRef,
        body: String,
    },
    /// A reply to either party's message, under forward secrecy as
    /// [`Self::Typed`] goes.
    Reply {
        target: MobileChatRegardingRef,
        body: String,
        forward_secret: Option<bool>,
    },
}

impl From<MobileChatSendRequest> for ChatComposeRequest {
    fn from(request: MobileChatSendRequest) -> Self {
        match request {
            MobileChatSendRequest::Typed {
                text,
                forward_secret,
            } => Self::Typed {
                text,
                forward_secret,
            },
            MobileChatSendRequest::Status { body } => Self::Status { body },
            MobileChatSendRequest::Text { body } => Self::Text { body },
            MobileChatSendRequest::Again {
                body,
                status,
                forward_secret,
            } => Self::Again {
                body,
                status,
                forward_secret,
            },
            MobileChatSendRequest::Edit { original, body } => Self::Edit { original, body },
            MobileChatSendRequest::Delete { original } => Self::Delete { original },
            MobileChatSendRequest::Reaction { target, body } => Self::Reaction { target, body },
            MobileChatSendRequest::Reply {
                target,
                body,
                forward_secret,
            } => Self::Reply {
                target,
                body,
                forward_secret,
            },
        }
    }
}

/// Why a send did not go out. Each says what became of the message.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileChatSendError {
    /// The session would not make the message. Nothing was kept.
    NotComposed { error: MobileMeshError },
    /// The message could not be kept, so it was not sent.
    NotSaved { error: MobileStoreError },
    /// The message could not be kept, and the session could not take it
    /// back either: its streams stand ahead of what is stored until the
    /// next session.
    NotSavedOrReset { error: MobileStoreError },
    /// The message was kept, but could not be queued; it is stored as not
    /// delivered.
    NotQueued { error: MobileMeshError },
    /// The message was kept, but could not be queued, and that could not be
    /// stored either: it may read as sending until the next session.
    NotQueuedOrRecorded { error: MobileMeshError },
    /// The session has no store to keep the message in.
    NoStore,
}

impl std::fmt::Display for MobileChatSendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotComposed { error } => write!(formatter, "CHAT_NOT_COMPOSED: {error}"),
            Self::NotSaved { error } => write!(formatter, "CHAT_NOT_SAVED: {error}"),
            Self::NotSavedOrReset { error } => {
                write!(formatter, "CHAT_NOT_SAVED_OR_RESET: {error}")
            }
            Self::NotQueued { error } => write!(formatter, "CHAT_NOT_QUEUED: {error}"),
            Self::NotQueuedOrRecorded { error } => {
                write!(formatter, "CHAT_NOT_QUEUED_OR_RECORDED: {error}")
            }
            Self::NoStore => formatter.write_str("CHAT_NO_STORE"),
        }
    }
}

impl std::error::Error for MobileChatSendError {}

pub(super) enum ChatStoreCommand {
    SilentTestsIn(Option<String>),
    Send {
        conversation_address: String,
        request: ChatComposeRequest,
        response: oneshot::Sender<Result<(), MobileChatSendError>>,
    },
}

/// The session's end of its chat store's thread. Dropping it ends the
/// thread, once it has finished what it is doing.
pub(super) struct ChatStore {
    commands: mpsc::UnboundedSender<ChatStoreCommand>,
    /// Makes the radio refuse every stored message, for the tests of what
    /// a send does then.
    #[cfg(test)]
    refuse_release: Arc<std::sync::atomic::AtomicBool>,
    /// How many times a batch could not be stored, for the tests of the
    /// retries.
    #[cfg(test)]
    failed_attempts: Arc<std::sync::atomic::AtomicU32>,
}

impl ChatStore {
    /// Start storing `session`'s chat in `store`, for `owner_identity_id`.
    /// `ready` is told whenever the worker reports a chat effect.
    pub(super) fn start(
        session: &Arc<MobileMeshSession>,
        store: Arc<MobileAppStore>,
        owner_identity_id: String,
        silent_tests_in: Option<String>,
        ready: Arc<Notify>,
        retry_delay: Duration,
    ) -> Result<Self, MobileMeshError> {
        let (commands, receiver) = mpsc::unbounded_channel();
        #[cfg(test)]
        let refuse_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(test)]
        let failed_attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let storer = Storer {
            session: Arc::downgrade(session),
            store,
            owner_identity_id,
            silent_tests_in,
            retry_delay,
            held: None,
            #[cfg(test)]
            refuse_release: refuse_release.clone(),
            #[cfg(test)]
            failed_attempts: failed_attempts.clone(),
        };
        std::thread::Builder::new()
            .name("umsh-chat-store".to_owned())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                else {
                    return;
                };
                runtime.block_on(storer.run(receiver, ready));
            })
            .map_err(|_| MobileMeshError::SessionUnavailable)?;
        Ok(Self {
            commands,
            #[cfg(test)]
            refuse_release,
            #[cfg(test)]
            failed_attempts,
        })
    }

    pub(super) fn send(&self, command: ChatStoreCommand) -> Result<(), MobileMeshError> {
        self.commands
            .send(command)
            .map_err(|_| MobileMeshError::SessionUnavailable)
    }
}

/// A batch taken from the worker and not yet stored.
struct HeldBatch {
    effects: ChatBatchEffects,
    attempts: u32,
}

struct Storer {
    /// Weak, so the thread does not keep the session alive.
    session: Weak<MobileMeshSession>,
    store: Arc<MobileAppStore>,
    owner_identity_id: String,
    silent_tests_in: Option<String>,
    retry_delay: Duration,
    held: Option<HeldBatch>,
    #[cfg(test)]
    refuse_release: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    failed_attempts: Arc<std::sync::atomic::AtomicU32>,
}

impl Storer {
    async fn run(
        mut self,
        mut commands: mpsc::UnboundedReceiver<ChatStoreCommand>,
        ready: Arc<Notify>,
    ) {
        let mut retry_at = None;
        loop {
            if retry_at.is_none() {
                let Some(session) = self.session.upgrade() else {
                    return;
                };
                if !self.store_waiting(&session) {
                    retry_at = Some(tokio::time::Instant::now() + self.retry_delay);
                }
            }
            tokio::select! {
                command = commands.recv() => match command {
                    None => return,
                    Some(ChatStoreCommand::SilentTestsIn(address)) => {
                        self.silent_tests_in = address;
                    }
                    Some(ChatStoreCommand::Send {
                        conversation_address,
                        request,
                        response,
                    }) => {
                        let Some(session) = self.session.upgrade() else {
                            return;
                        };
                        let result = self.send(&session, conversation_address, request).await;
                        let _ = response.send(result);
                    }
                },
                () = ready.notified() => {}
                () = sleep_until(retry_at) => retry_at = None,
            }
        }
    }

    /// Store everything the worker has reported, batch by batch. Returns
    /// `false` when a batch could not be stored and is to be tried again
    /// later.
    fn store_waiting(&mut self, session: &MobileMeshSession) -> bool {
        loop {
            if self.held.is_none() {
                let events = session
                    .chat_events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .try_iter()
                    .collect::<Vec<_>>();
                if events.is_empty() {
                    return true;
                }
                self.held = Some(held_batch(events));
            }
            let Some(held) = self.held.as_mut() else {
                return true;
            };
            let channel_digests = session
                .channel_digests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let context = ChatBatchContext {
                owner_identity_id: &self.owner_identity_id,
                channel_digests: &channel_digests,
                silent_tests_in: self.silent_tests_in.as_deref(),
                now_ms: unix_ms(),
            };
            match self.store.apply_chat_batch(&context, &held.effects) {
                Ok(applied) => {
                    self.held = None;
                    for (request_id, payload) in applied.archive_answers {
                        answer_lookup(session, request_id, payload);
                    }
                    session.publish_chat_changes(applied.changes);
                }
                Err(error) => {
                    held.attempts += 1;
                    #[cfg(test)]
                    self.failed_attempts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if held.attempts < ATTEMPT_LIMIT {
                        log::warn!(
                            "could not store a chat batch (attempt {} of {ATTEMPT_LIMIT}): {error}",
                            held.attempts,
                        );
                        return false;
                    }
                    let Some(held) = self.held.take() else {
                        return true;
                    };
                    // The lookups it carried still want an answer.
                    for lookup in &held.effects.archive_lookups {
                        answer_lookup(session, lookup.request_id, None);
                    }
                    log::error!(
                        "gave up storing a chat batch after {} attempts ({error}): \
                         {} message changes and {} delivery reports are lost",
                        held.attempts,
                        held.effects.mutations.len(),
                        held.effects.deliveries.len(),
                    );
                    session.publish_chat_changes(MobileChatChangesRecord {
                        all_conversations: true,
                        ..MobileChatChangesRecord::default()
                    });
                }
            }
        }
    }

    /// Compose, keep, then release: nothing goes on the air that is not
    /// stored first, and a stored message that cannot go is stored as not
    /// delivered. Whatever is stored is reported as a change, so the
    /// transcript is redrawn even when the caller has stopped waiting.
    async fn send(
        &self,
        session: &MobileMeshSession,
        conversation_address: String,
        request: ChatComposeRequest,
    ) -> Result<(), MobileChatSendError> {
        let owner = &self.owner_identity_id;
        let changed = || {
            session.publish_chat_changes(MobileChatChangesRecord {
                conversations: vec![conversation_address.clone()],
                ..MobileChatChangesRecord::default()
            });
        };
        let batch = session
            .compose_chat(conversation_address.clone(), client_token(), request)
            .await
            .map_err(|error| MobileChatSendError::NotComposed { error })?;
        if let Err(error) =
            self.store
                .commit_chat_compose_batch(owner.clone(), batch.clone(), unix_ms())
        {
            let reset = match self.store.chat_checkpoints(owner.clone()) {
                Ok(checkpoints) => session
                    .reject_chat_batch(batch.batch_id, checkpoints)
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            return Err(if reset {
                MobileChatSendError::NotSaved { error }
            } else {
                MobileChatSendError::NotSavedOrReset { error }
            });
        }
        changed();
        if let Err(error) = self.release(session, batch.batch_id).await {
            let recorded = self
                .store
                .mark_chat_compose_batch_failed(owner.clone(), batch);
            changed();
            return Err(match recorded {
                Ok(()) => MobileChatSendError::NotQueued { error },
                Err(_) => MobileChatSendError::NotQueuedOrRecorded { error },
            });
        }
        Ok(())
    }

    /// Release a stored batch's frames to the radio.
    async fn release(
        &self,
        session: &MobileMeshSession,
        batch_id: u64,
    ) -> Result<(), MobileMeshError> {
        #[cfg(test)]
        if self
            .refuse_release
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(MobileMeshError::SendFailed);
        }
        session.commit_chat_batch(batch_id).await
    }
}

/// Sleep until `deadline`, or forever without one.
async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn held_batch(events: Vec<MobileChatWorkerEvent>) -> HeldBatch {
    HeldBatch {
        effects: effects(events),
        attempts: 0,
    }
}

/// The worker's chat events, sorted by kind.
pub(super) fn effects(events: Vec<MobileChatWorkerEvent>) -> ChatBatchEffects {
    let mut effects = ChatBatchEffects::default();
    for event in events {
        match event {
            MobileChatWorkerEvent::Mutation(record) => effects.mutations.push(record),
            MobileChatWorkerEvent::Resent(record) => effects.resends.push(record),
            MobileChatWorkerEvent::Delivery(record) => effects.deliveries.push(record),
            MobileChatWorkerEvent::Repeats(record) => effects.repeats.push(record),
            MobileChatWorkerEvent::ArchiveLookup(record) => effects.archive_lookups.push(record),
            MobileChatWorkerEvent::SenderResolution(record) => {
                effects.sender_resolutions.push(record);
            }
        }
    }
    effects
}

/// Answer a repair request with what the store holds. Best effort: the
/// answer travels over the radio, which can be gone.
fn answer_lookup(session: &MobileMeshSession, request_id: u32, payload: Option<Vec<u8>>) {
    let (kind, payload) = match payload {
        Some(payload) => (MobileChatArchiveResultKind::Found, payload),
        None => (MobileChatArchiveResultKind::Unknown, Vec::new()),
    };
    let _ = session.apply_chat_archive_result(request_id, kind, payload);
}

/// A client token for a compose: never zero.
fn client_token() -> u32 {
    loop {
        let token = rand::random::<u32>();
        if token != 0 {
            return token;
        }
    }
}

/// Now, in milliseconds since the Unix epoch, as the store stamps rows.
fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use umsh_crypto::NodeIdentity as _;
    use umsh_crypto::software::SoftwareIdentity;

    use super::super::MobilePeerRegistrationRecord;

    use super::*;
    use crate::store::{MobileChatNotificationRecord, MobilePeerUpsertRecord};
    use crate::{
        MobileCounterStore, MobileIdentity, MobileMeshRxRecord, MobileStoredChatDeliveryState,
    };

    const OWNER: &str = "me";

    fn identity(seed: u8) -> Arc<MobileIdentity> {
        let identity = SoftwareIdentity::from_secret_bytes(&[seed; 32]);
        let public_identity = crate::public_identity_record(identity.public_key());
        Arc::new(MobileIdentity {
            identity: Mutex::new(Some(identity)),
            public_identity,
        })
    }

    fn address(identity: &MobileIdentity) -> String {
        identity.public_identity.canonical_address.clone()
    }

    /// A store at `path` holding this phone's identity and its one peer,
    /// or with `known` false, holding nothing at all.
    fn store(path: &std::path::Path, own: &str, peer: &str, known: bool) -> Arc<MobileAppStore> {
        let store = MobileAppStore::open(path.display().to_string()).unwrap();
        if known {
            know(&store, own, peer);
        }
        store
    }

    fn know(store: &MobileAppStore, own: &str, peer: &str) {
        store
            .upsert_identity(OWNER.to_owned(), own.to_owned(), 1)
            .unwrap();
        store
            .upsert_peer(
                OWNER.to_owned(),
                peer.to_owned(),
                MobilePeerUpsertRecord {
                    is_saved: true,
                    ..MobilePeerUpsertRecord::default()
                },
            )
            .unwrap();
    }

    async fn session(
        directory: &std::path::Path,
        identity: &Arc<MobileIdentity>,
        peer: &str,
    ) -> Arc<MobileMeshSession> {
        let counters = MobileCounterStore::new(
            directory
                .join(format!("counters-{}", address(identity)))
                .display()
                .to_string(),
        )
        .unwrap();
        let session = MobileMeshSession::start(identity.clone(), counters)
            .await
            .unwrap();
        session
            .register_peers(vec![MobilePeerRegistrationRecord {
                address: peer.to_owned(),
                mobile: false,
            }])
            .await
            .unwrap();
        session
    }

    fn rx(data: Vec<u8>) -> MobileMeshRxRecord {
        MobileMeshRxRecord {
            data,
            rssi_dbm: Some(-55),
            lqi: Some(200),
            snr_cb: Some(70),
            was_buffered: false,
            was_acknowledged: false,
            age_seconds: 0,
        }
    }

    /// Carry what each session puts on the air to the other, once, and
    /// return what each poll said had changed.
    fn exchange(
        alice: &MobileMeshSession,
        bob: &MobileMeshSession,
    ) -> (MobileChatChangesRecord, MobileChatChangesRecord) {
        let mut changes = (
            MobileChatChangesRecord::default(),
            MobileChatChangesRecord::default(),
        );
        for (from, to, changed) in [(alice, bob, &mut changes.0), (bob, alice, &mut changes.1)] {
            let update = from.poll_update();
            for frame in update.outbound_frames {
                from.complete_outbound_frame(frame.id, true).unwrap();
                to.receive(rx(frame.data)).unwrap();
            }
            if let Some(update) = update.chat_changes {
                changed.merge(update);
            }
        }
        changes
    }

    /// How many times `session`'s chat store could not store a batch.
    fn failed_attempts(session: &MobileMeshSession) -> u32 {
        session
            .chat_store
            .get()
            .unwrap()
            .failed_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the newest message in the store's conversation with `peer`
    /// is acknowledged.
    fn acknowledged(store: &MobileAppStore, peer: &str) -> bool {
        store
            .chat_message_page_newest(OWNER.to_owned(), peer.to_owned(), 1)
            .unwrap()
            .messages
            .first()
            .is_some_and(|message| {
                message.delivery_state == Some(MobileStoredChatDeliveryState::Acknowledged)
            })
    }

    /// Carry frames between `alice`, who has a store, and `bob`, who has
    /// none yet, until Alice's newest message to Bob is acknowledged: Bob
    /// has heard it, and holds it for a store.
    fn deliver_to_storeless(
        alice: &MobileMeshSession,
        alice_store: &MobileAppStore,
        bob: &MobileMeshSession,
        bob_address: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !acknowledged(alice_store, bob_address) {
            assert!(Instant::now() < deadline, "the message did not arrive");
            exchange(alice, bob);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn a_stored_session_keeps_what_it_sends_and_hears() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(61), identity(62));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            true,
        );
        let bob_store = store(
            &directory.path().join("bob.sqlite"),
            &bob_address,
            &alice_address,
            true,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        let bob = session(directory.path(), &bob_identity, &alice_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        bob.clone()
            .attach_chat_store(bob_store.clone(), OWNER.to_owned(), None)
            .unwrap();

        alice
            .send_chat(
                bob_address.clone(),
                MobileChatSendRequest::Text {
                    body: "hello, stored".to_owned(),
                },
            )
            .await
            .unwrap();
        // Stored before it went anywhere.
        let sent = alice_store
            .chat_message_page_newest(OWNER.to_owned(), bob_address.clone(), 10)
            .unwrap()
            .messages;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].body, "hello, stored");

        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut alice_changes, mut bob_changes) = Default::default();
        loop {
            let (alice_now, bob_now) = exchange(&alice, &bob);
            MobileChatChangesRecord::merge(&mut alice_changes, alice_now);
            MobileChatChangesRecord::merge(&mut bob_changes, bob_now);
            let delivered = alice_store
                .chat_message_page_newest(OWNER.to_owned(), bob_address.clone(), 10)
                .unwrap()
                .messages[0]
                .delivery_state
                == Some(MobileStoredChatDeliveryState::Acknowledged);
            // The store is written before the change is reported, so the
            // report is waited for too.
            if delivered
                && !bob_changes.notifications.is_empty()
                && alice_changes.conversations.contains(&bob_address)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the message was not stored at both ends"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let bob_changes: MobileChatChangesRecord = bob_changes;
        assert_eq!(bob_changes.conversations, vec![alice_address.clone()]);
        assert!(!bob_changes.all_conversations);
        match &bob_changes.notifications[..] {
            [MobileChatNotificationRecord::Message { target }] => {
                assert_eq!(target.conversation_address, alice_address);
                assert_eq!(target.body, "hello, stored");
            }
            other => panic!("one message to tell of, not {other:?}"),
        }
        let alice_changes: MobileChatChangesRecord = alice_changes;
        assert_eq!(alice_changes.conversations, vec![bob_address.clone()]);
        assert!(alice_changes.notifications.is_empty());
        // The message opened Bob's conversation with Alice.
        let conversations = bob_store
            .list_direct_conversations(OWNER.to_owned())
            .unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].node.public_address, alice_address);
        let received = bob_store
            .chat_message_page_newest(OWNER.to_owned(), alice_address.clone(), 10)
            .unwrap()
            .messages;
        assert_eq!(received.len(), 1);
        assert!(!received[0].outbound);
    }

    #[tokio::test]
    async fn a_batch_that_cannot_be_stored_is_stored_on_a_later_try() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(63), identity(64));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            true,
        );
        // Bob's store does not know Bob's identity yet, so nothing of his
        // can be stored.
        let bob_store = store(
            &directory.path().join("bob.sqlite"),
            &bob_address,
            &alice_address,
            false,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        let bob = session(directory.path(), &bob_identity, &alice_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store, OWNER.to_owned(), None)
            .unwrap();
        bob.clone()
            .attach_chat_store_retrying_after(
                bob_store.clone(),
                OWNER.to_owned(),
                None,
                Duration::from_millis(200),
            )
            .unwrap();

        alice
            .send_chat(
                bob_address.clone(),
                MobileChatSendRequest::Text {
                    body: "try again".to_owned(),
                },
            )
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut bob_changes = MobileChatChangesRecord::default();
        let mut known = false;
        loop {
            let (_, bob_now) = exchange(&alice, &bob);
            bob_changes.merge(bob_now);
            if !known && failed_attempts(&bob) == 1 {
                // Between the first try and the second.
                know(&bob_store, &bob_address, &alice_address);
                known = true;
            }
            if !bob_changes.notifications.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the batch was not stored on a later try: {bob_changes:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(known);
        assert_eq!(failed_attempts(&bob), 1, "stored on the second try");
        assert_eq!(bob_changes.notifications.len(), 1);
        let received = bob_store
            .chat_message_page_newest(OWNER.to_owned(), alice_address, 10)
            .unwrap()
            .messages;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].body, "try again");
    }

    #[tokio::test]
    async fn a_batch_that_never_stores_is_given_up() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(65), identity(66));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            true,
        );
        let bob_store = store(
            &directory.path().join("bob.sqlite"),
            &bob_address,
            &alice_address,
            false,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        let bob = session(directory.path(), &bob_identity, &alice_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store, OWNER.to_owned(), None)
            .unwrap();
        bob.clone()
            .attach_chat_store_retrying_after(
                bob_store,
                OWNER.to_owned(),
                None,
                Duration::from_millis(10),
            )
            .unwrap();
        alice
            .send_chat(
                bob_address,
                MobileChatSendRequest::Text {
                    body: "lost".to_owned(),
                },
            )
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut bob_changes = MobileChatChangesRecord::default();
        while !bob_changes.all_conversations {
            assert!(Instant::now() < deadline, "the batch was never given up");
            let (_, bob_now) = exchange(&alice, &bob);
            bob_changes.merge(bob_now);
            std::thread::sleep(Duration::from_millis(5));
        }
        // Every transcript may now be out of date.
        assert_eq!(failed_attempts(&bob), ATTEMPT_LIMIT);
        assert!(bob_changes.notifications.is_empty());
    }

    #[tokio::test]
    async fn what_arrives_before_the_store_comes_is_stored() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(69), identity(70));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            true,
        );
        let bob_store = store(
            &directory.path().join("bob.sqlite"),
            &bob_address,
            &alice_address,
            true,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        let bob = session(directory.path(), &bob_identity, &alice_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        alice
            .send_chat(
                bob_address.clone(),
                MobileChatSendRequest::Text {
                    body: "early".to_owned(),
                },
            )
            .await
            .unwrap();
        deliver_to_storeless(&alice, &alice_store, &bob, &bob_address);
        let deadline = Instant::now() + Duration::from_secs(10);
        bob.clone()
            .attach_chat_store(bob_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        let mut bob_changes = MobileChatChangesRecord::default();
        while bob_changes.notifications.is_empty() {
            assert!(
                Instant::now() < deadline,
                "the waiting batch was not stored"
            );
            let (_, bob_now) = exchange(&alice, &bob);
            bob_changes.merge(bob_now);
            std::thread::sleep(Duration::from_millis(5));
        }
        let received = bob_store
            .chat_message_page_newest(OWNER.to_owned(), alice_address, 10)
            .unwrap()
            .messages;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].body, "early");
    }

    #[tokio::test]
    async fn a_message_that_cannot_be_kept_is_not_sent_and_the_next_one_is() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(71), identity(72));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        // Alice's store does not hold her identity yet, so nothing of hers
        // can be kept.
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            false,
        );
        let bob_store = store(
            &directory.path().join("bob.sqlite"),
            &bob_address,
            &alice_address,
            true,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        let bob = session(directory.path(), &bob_identity, &alice_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        bob.clone()
            .attach_chat_store(bob_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        let send = |body: &str| {
            alice.send_chat(
                bob_address.clone(),
                MobileChatSendRequest::Text {
                    body: body.to_owned(),
                },
            )
        };
        assert!(matches!(
            send("not kept").await,
            Err(MobileChatSendError::NotSaved { .. })
        ));
        assert_eq!(alice.poll_update().chat_changes, None, "nothing changed");

        // The session took the message back, so the next one is composed
        // rather than refused as one too many.
        know(&alice_store, &alice_address, &bob_address);
        send("kept").await.unwrap();
        let stored = alice_store
            .chat_message_page_newest(OWNER.to_owned(), bob_address.clone(), 10)
            .unwrap()
            .messages;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].body, "kept");

        // Only the kept one went on the air.
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut alice_changes, mut bob_changes) = Default::default();
        while MobileChatChangesRecord::is_empty(&bob_changes) {
            assert!(Instant::now() < deadline, "the kept message did not arrive");
            let (alice_now, bob_now) = exchange(&alice, &bob);
            MobileChatChangesRecord::merge(&mut alice_changes, alice_now);
            MobileChatChangesRecord::merge(&mut bob_changes, bob_now);
            std::thread::sleep(Duration::from_millis(5));
        }
        // The send itself is reported, whoever is still waiting on it.
        assert!(alice_changes.conversations.contains(&bob_address));
        let received = bob_store
            .chat_message_page_newest(OWNER.to_owned(), alice_address, 10)
            .unwrap()
            .messages;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].body, "kept");
    }

    #[tokio::test]
    async fn a_kept_message_the_radio_refuses_is_stored_as_not_delivered() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(73), identity(74));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            true,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        alice
            .chat_store
            .get()
            .unwrap()
            .refuse_release
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            alice
                .send_chat(
                    bob_address.clone(),
                    MobileChatSendRequest::Text {
                        body: "refused".to_owned(),
                    },
                )
                .await,
            Err(MobileChatSendError::NotQueued { .. })
        ));
        let update = alice.poll_update();
        assert!(update.outbound_frames.is_empty(), "nothing went out");
        // Redrawn all the same: the message is there, as one that failed.
        assert_eq!(
            update.chat_changes.map(|changes| changes.conversations),
            Some(vec![bob_address.clone()])
        );
        let stored = alice_store
            .chat_message_page_newest(OWNER.to_owned(), bob_address, 10)
            .unwrap()
            .messages;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].body, "refused");
        assert_eq!(
            stored[0].delivery_state,
            Some(MobileStoredChatDeliveryState::Undelivered)
        );
    }

    #[tokio::test]
    async fn what_waited_for_the_store_is_stored_under_the_setting_it_came_with() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(75), identity(76));
        let (alice_address, bob_address) = (address(&alice_identity), address(&bob_identity));
        let alice_store = store(
            &directory.path().join("alice.sqlite"),
            &alice_address,
            &bob_address,
            true,
        );
        let bob_store = store(
            &directory.path().join("bob.sqlite"),
            &bob_address,
            &alice_address,
            true,
        );
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        let bob = session(directory.path(), &bob_identity, &alice_address).await;
        alice
            .clone()
            .attach_chat_store(alice_store.clone(), OWNER.to_owned(), None)
            .unwrap();
        alice
            .send_chat(
                bob_address.clone(),
                MobileChatSendRequest::Text {
                    body: "TEST: radio check".to_owned(),
                },
            )
            .await
            .unwrap();
        // The message reaches Bob before he has a store.
        deliver_to_storeless(&alice, &alice_store, &bob, &bob_address);
        let deadline = Instant::now() + Duration::from_secs(10);
        bob.clone()
            .attach_chat_store(
                bob_store.clone(),
                OWNER.to_owned(),
                Some(alice_address.clone()),
            )
            .unwrap();
        let mut stored = Vec::new();
        while stored.is_empty() {
            assert!(
                Instant::now() < deadline,
                "the waiting batch was not stored"
            );
            std::thread::sleep(Duration::from_millis(5));
            stored = bob_store
                .chat_message_page_newest(OWNER.to_owned(), alice_address.clone(), 10)
                .unwrap()
                .messages;
        }
        // Silent, so not counted as unread.
        let conversations = bob_store
            .list_direct_conversations(OWNER.to_owned())
            .unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].unread_count, 0);
    }

    #[tokio::test]
    async fn a_send_without_a_store_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let (alice_identity, bob_identity) = (identity(67), identity(68));
        let bob_address = address(&bob_identity);
        let alice = session(directory.path(), &alice_identity, &bob_address).await;
        assert_eq!(
            alice
                .send_chat(
                    bob_address,
                    MobileChatSendRequest::Text {
                        body: "nowhere to keep it".to_owned(),
                    },
                )
                .await,
            Err(MobileChatSendError::NoStore)
        );
    }
}
