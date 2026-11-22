//! The event pipeline: what the driver and the session report, taken in
//! order on each wake.
//!
//! Per wake: the driver's host releases, then every state it passed
//! through in order, then its pushes; then the session's update in today's
//! order (chat, pings, management, advertisements, destination hints,
//! forward secrecy, meet, hearings). Each step that changes what the policy
//! pass reads marks it dirty; nothing here waits for the pass.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use super::MobileAppError;
use super::records::{
    MobileAppChangesRecord, MobileNotificationEventRecord, MobileNotificationReactionRecord,
};
use super::worker::Worker;
use crate::meet::{MobileMeetContactRecord, MobileMeetExchange, MobileMeetStateRecord};
use crate::mobile_mesh::{MobileMeshAdvertisementRecord, MobileMeshPeerHeardRecord};
use crate::radio_driver::{MobileRadioPhase, MobileRadioStateRecord};
use crate::store::{
    MobileChatChangesRecord, MobileChatNotificationRecord, MobilePeerUpsertRecord,
    MobileStoredChatDeliveryFailureRecord, MobileStoredNodeKind, MobileStoredNodeRecord,
};
use crate::ulcp::UlcpHostOwnership;
use crate::{IdentitySignatureState, NodeHint, NodeUriPreviewRecord};

/// Transient peers kept past this many go, oldest heard first.
const TRANSIENT_PEERS_KEPT: u32 = 256;
/// A hearing within this long of the last one written for the same peer
/// is not written again, unless a watch is armed on the peer.
const HEARING_SKIP_MS: i64 = 1_000;
/// Prefix of a channel conversation's address.
const CHANNEL_ADDRESS_PREFIX: &str = "ch:";

#[derive(Default)]
pub(super) struct PipelineState {
    /// When each peer's hearing was last written, on the monotonic clock.
    heard_at: HashMap<String, i64>,
    /// The meet's state as the session last reported it.
    pub(super) meet: Option<MobileMeetStateRecord>,
    /// The contact the current `Exchanged` state was recorded for.
    recorded_exchange: Option<String>,
    /// Whether Add Peer wants the meet open.
    pub(super) meet_wanted: bool,
    /// What the meet was last asked to become, until the session reports
    /// it, so one change is asked for once.
    meet_requested: Option<bool>,
    /// Conversations the pass has seen. A chat batch naming another opened
    /// one, which the pass's mute lists include.
    pub(super) known_conversations: HashSet<String>,
}

/// Whether `state` is this phone's radio, attached.
pub(super) fn carries_this_phone(state: Option<&MobileRadioStateRecord>) -> bool {
    state.is_some_and(|state| {
        state.phase == MobileRadioPhase::Attached && state.host == UlcpHostOwnership::Ours
    })
}

/// Whether a request already made survives `state`: configuring the radio
/// does not end its session.
fn session_continues(state: &MobileRadioStateRecord) -> bool {
    matches!(
        state.phase,
        MobileRadioPhase::Attached | MobileRadioPhase::Configuring
    )
}

impl Worker {
    /// Take the driver's states, releases and pushes.
    pub(super) fn take_driver_update(self: &Rc<Self>) {
        let Some(driver) = self.driver() else {
            return;
        };
        let update = driver.take_core_update();
        // A release first, so a detach that follows it does not record the
        // claim the release just ended.
        for key in update.host_releases {
            self.host_released(&key);
        }
        for state in update.states {
            self.radio_state(Some(state));
        }
        if !update.pushed_properties.is_empty() || update.pushed_properties_dropped > 0 {
            self.shared.publish(|_| MobileAppChangesRecord {
                property_pushes: update.pushed_properties,
                property_pushes_dropped: update.pushed_properties_dropped,
                ..MobileAppChangesRecord::default()
            });
        }
    }

    /// One state the driver passed through, or `None` when the core no
    /// longer has a driver, which is a detach.
    pub(super) fn radio_state(self: &Rc<Self>, state: Option<MobileRadioStateRecord>) {
        let previous = self.shared.snapshot().radio.clone();
        if previous == state {
            return;
        }
        if !state.as_ref().is_some_and(session_continues) {
            self.fail_waiters(&MobileAppError::NoRadio);
        }
        let carried = carries_this_phone(previous.as_ref());
        let carries = carries_this_phone(state.as_ref());
        self.radio_transition(previous.as_ref(), state.as_ref());
        let attached_host = state
            .as_ref()
            .filter(|_| carries)
            .and_then(|state| state.device_key.clone())
            .and_then(|key| crate::inspect_public_identity_bytes(key).ok())
            .map(|identity| identity.canonical_address);
        self.shared.publish(|snapshot| {
            snapshot.attached_host = attached_host;
            MobileAppChangesRecord::default()
        });
        self.radio_changed(state);
        if carried != carries {
            self.settle_meet();
        }
    }

    /// Take the session's update.
    pub(super) fn take_session_update(self: &Rc<Self>) {
        let Some(session) = self.session() else {
            return;
        };
        let update = session.take_update();
        // With no radio there is nowhere for a frame to go: fail it now,
        // or the session's pump would wait out its completion timeout.
        for frame in update.outbound_frames {
            let _ = session.complete_outbound_frame(frame.id, false);
        }
        if let Some(changes) = update.chat_changes {
            self.chat_changed(changes);
        }
        for event in update.ping_events {
            self.ping_event(event);
        }
        for event in update.management_events {
            self.management_event(event);
        }
        if !update.advertisement_events.is_empty() {
            for advertisement in update.advertisement_events {
                self.advertisement(advertisement);
            }
        }
        if let Some(hints) = update.local_destination_hints {
            self.destination_hints_changed(hints);
        }
        if let Some(forward_secret) = update.forward_secret_conversations {
            self.shared.publish(|snapshot| {
                snapshot
                    .forward_secret_conversations
                    .clone_from(&forward_secret);
                MobileAppChangesRecord {
                    forward_secret_conversations: Some(forward_secret),
                    ..MobileAppChangesRecord::default()
                }
            });
        }
        if let Some(meet) = update.meet {
            self.pipeline.borrow_mut().meet_requested = None;
            self.meet_changed(Some(meet));
            // Add Peer may have changed its mind while the meet moved.
            self.settle_meet();
        }
        if !update.peer_heard_events.is_empty() {
            self.heard(&update.peer_heard_events);
        }
    }

    /// The session ended: fail everyone waiting on it, and forget what
    /// only it knew.
    pub(super) fn session_ended(&self) {
        self.fail_waiters(&MobileAppError::NotRunning);
        let mut pipeline = self.pipeline.borrow_mut();
        pipeline.heard_at.clear();
        pipeline.recorded_exchange = None;
        pipeline.meet_requested = None;
        pipeline.known_conversations.clear();
        drop(pipeline);
        self.meet_changed(None);
    }

    /// A trusted advertisement: kept as a transient peer, and a hearing.
    fn advertisement(&self, advertisement: MobileMeshAdvertisementRecord) {
        let Some(owner) = self.owner() else {
            return;
        };
        if advertisement.peer_address == owner {
            return;
        }
        let Ok(identity) = crate::decode_node_identity(
            advertisement.peer_address.clone(),
            advertisement.payload.clone(),
        ) else {
            return;
        };
        // A broadcast must carry a valid signature; an unsigned bundle is
        // trusted only when the frame that brought it was authenticated.
        let trusted = match identity.signature {
            IdentitySignatureState::Valid => true,
            IdentitySignatureState::Unsigned => advertisement.source_authenticated,
            IdentitySignatureState::Invalid => false,
        };
        if !trusted {
            return;
        }
        let now_ms = self.clock.now_ms();
        let address = advertisement.peer_address;
        // It arrived now, so it replaces whatever is stored: only a link's
        // bundle, of unknown age, must earn that (`link_identity_replaces`).
        let stored = self
            .store
            .upsert_peer(
                owner.clone(),
                address.clone(),
                MobilePeerUpsertRecord {
                    advertised_name: identity.name,
                    node_kind: Some(node_kind(identity.role_code)),
                    advertisement: Some(advertisement.payload),
                    advertisement_authenticated: advertisement.source_authenticated,
                    advertisement_received_at_ms: Some(now_ms),
                    ..MobilePeerUpsertRecord::default()
                },
            )
            .and_then(|()| {
                let fired = self
                    .store
                    .touch_last_heard(owner.clone(), address.clone(), now_ms)?;
                self.store
                    .enforce_transient_retention(owner, TRANSIENT_PEERS_KEPT)?;
                Ok(fired)
            });
        match stored {
            Ok(fired) => {
                self.pipeline
                    .borrow_mut()
                    .heard_at
                    .insert(address.clone(), self.clock.monotonic_ms());
                self.peers_changed(fired.then_some(address));
            }
            Err(error) => {
                log::error!(error:? = error; "a received advertisement was not kept");
            }
        }
    }

    /// Frames from peers were accepted: note when each was heard.
    fn heard(&self, hearings: &[MobileMeshPeerHeardRecord]) {
        let Some(owner) = self.owner() else {
            return;
        };
        let Ok(nodes) = self.store.list_nodes(owner.clone()) else {
            return;
        };
        let peers = HeardPeers::new(&nodes);
        for hearing in hearings {
            let Some(node) = peers.resolve(hearing) else {
                continue;
            };
            let now = self.clock.monotonic_ms();
            let recent = self
                .pipeline
                .borrow()
                .heard_at
                .get(&node.public_address)
                .is_some_and(|at| now - at < HEARING_SKIP_MS);
            if recent && !node.notify_when_heard {
                continue;
            }
            let address = node.public_address.clone();
            match self
                .store
                .touch_last_heard(owner.clone(), address.clone(), self.clock.now_ms())
            {
                Ok(fired) => {
                    self.pipeline
                        .borrow_mut()
                        .heard_at
                        .insert(address.clone(), now);
                    self.peers_changed(fired.then_some(address));
                }
                Err(error) => log::warn!(error:? = error; "a hearing was not kept"),
            }
        }
    }

    /// Forget what the pipeline keeps about a conversation or a peer that
    /// was deleted: a chat batch that opens it again is then new to the
    /// pass, and its next hearing is written.
    pub(super) fn forget_conversation(&self, address: &str) {
        let mut pipeline = self.pipeline.borrow_mut();
        pipeline.heard_at.remove(address);
        pipeline.known_conversations.remove(address);
    }

    /// Peers changed, and maybe one being watched for was heard.
    pub(super) fn peers_changed(&self, heard: Option<String>) {
        self.shared.publish(|_| MobileAppChangesRecord {
            peers_changed: true,
            notifications: heard
                .map(|address| MobileNotificationEventRecord::PeerHeard { address })
                .into_iter()
                .collect(),
            ..MobileAppChangesRecord::default()
        });
    }

    /// What one chat batch, or several merged, stored.
    fn chat_changed(&self, changes: MobileChatChangesRecord) {
        let MobileChatChangesRecord {
            conversations,
            all_conversations,
            notifications,
            delivery_failures,
            heard_watches,
        } = changes;
        // A direct conversation the pass has not seen changes what it
        // writes to the radio; a channel's never does.
        let mut opened = false;
        {
            let mut pipeline = self.pipeline.borrow_mut();
            for address in &conversations {
                if !address.starts_with(super::bootstrap::CHANNEL_ADDRESS_PREFIX) {
                    opened |= pipeline.known_conversations.insert(address.clone());
                }
            }
        }
        let mut events: Vec<MobileNotificationEventRecord> = Vec::new();
        let mut mutes = None;
        for failure in delivery_failures {
            let mutes = mutes.get_or_insert_with(|| self.notification_mutes());
            if let Some(event) = mutes.delivery_failure(failure) {
                events.push(event);
            }
        }
        events.extend(
            heard_watches
                .into_iter()
                .map(|address| MobileNotificationEventRecord::PeerHeard { address }),
        );
        if !notifications.is_empty() {
            let mutes = mutes.get_or_insert_with(|| self.notification_mutes());
            events.extend(mutes.arrivals(notifications));
        }
        // A batch moves last-heard and the lists' newest messages.
        let touched = !conversations.is_empty() || all_conversations || !events.is_empty();
        self.shared.publish(|_| MobileAppChangesRecord {
            peers_changed: touched,
            conversations_changed: touched,
            transcripts: conversations,
            all_transcripts: all_conversations,
            notifications: events,
            ..MobileAppChangesRecord::default()
        });
        if opened {
            self.policy_triggered();
        }
    }

    /// What decides whether a conversation may notify, read once per
    /// batch.
    fn notification_mutes(&self) -> Mutes {
        let Some(owner) = self.owner() else {
            return Mutes::default();
        };
        let channels: HashMap<String, bool> = self
            .store
            .channels(owner.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|channel| {
                (
                    channel.id,
                    channel.joined_phone && channel.notifications_enabled,
                )
            })
            .collect();
        let channel_conversations = self
            .store
            .list_channel_conversations(owner.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|conversation| {
                let enabled = channels
                    .get(&conversation.channel_id)
                    .copied()
                    .unwrap_or(false);
                (
                    conversation.conversation_address,
                    (conversation.channel_id, enabled),
                )
            })
            .collect();
        let direct = self
            .store
            .list_direct_conversations(owner)
            .unwrap_or_default()
            .into_iter()
            .map(|conversation| {
                (
                    conversation.node.public_address,
                    conversation.notifications_enabled,
                )
            })
            .collect();
        Mutes {
            channels: channel_conversations,
            direct,
        }
    }

    /// The radio's filter should carry these destinations.
    fn destination_hints_changed(&self, hints: Vec<Vec<u8>>) {
        self.set_destination_hints(hints);
    }

    /// The meet's state changed, or the meet closed with its session.
    pub(super) fn meet_changed(&self, meet: Option<MobileMeetStateRecord>) {
        if self.pipeline.borrow().meet == meet {
            return;
        }
        self.pipeline.borrow_mut().meet.clone_from(&meet);
        let exchanged = match meet.as_ref().map(|meet| &meet.exchange) {
            Some(MobileMeetExchange::Exchanged { contact }) => self.record_exchanged(contact),
            _ => {
                self.pipeline.borrow_mut().recorded_exchange = None;
                None
            }
        };
        self.shared.publish(|snapshot| {
            snapshot.meet.clone_from(&meet);
            MobileAppChangesRecord {
                meet_changed: true,
                meet,
                peers_changed: exchanged.is_some(),
                exchanged_peer: exchanged,
                ..MobileAppChangesRecord::default()
            }
        });
    }

    /// Store the peer an exchange brought, once per exchange. The in-person
    /// code confirmed it, so no signature is asked of its bundle.
    fn record_exchanged(&self, contact: &MobileMeetContactRecord) -> Option<String> {
        if self.pipeline.borrow().recorded_exchange.as_ref() == Some(&contact.peer_address) {
            return None;
        }
        self.pipeline.borrow_mut().recorded_exchange = Some(contact.peer_address.clone());
        let owner = self.owner()?;
        if contact.peer_address == owner {
            return None;
        }
        let identity = crate::decode_node_identity(
            contact.peer_address.clone(),
            contact.identity_bundle.clone(),
        )
        .ok();
        // Exchanged now, so it replaces whatever is stored, as a heard
        // advertisement does.
        let stored = self.store.upsert_peer(
            owner,
            contact.peer_address.clone(),
            MobilePeerUpsertRecord {
                advertised_name: identity.as_ref().and_then(|identity| identity.name.clone()),
                node_kind: identity
                    .as_ref()
                    .map(|identity| node_kind(identity.role_code)),
                advertisement: Some(contact.identity_bundle.clone()),
                advertisement_authenticated: false,
                advertisement_received_at_ms: Some(self.clock.now_ms()),
                ..MobilePeerUpsertRecord::default()
            },
        );
        match stored {
            Ok(()) => Some(contact.peer_address.clone()),
            Err(error) => {
                log::error!(error:? = error; "an exchanged contact was not kept");
                None
            }
        }
    }

    /// Open the meet when Add Peer wants it and the radio carries this
    /// phone; close it otherwise.
    pub(super) fn settle_meet(self: &Rc<Self>) {
        let wanted = self.pipeline.borrow().meet_wanted
            && carries_this_phone(self.shared.snapshot().radio.as_ref());
        let open = self
            .pipeline
            .borrow()
            .meet
            .as_ref()
            .is_some_and(|meet| meet.exchange != MobileMeetExchange::Closed);
        if wanted == open || self.pipeline.borrow().meet_requested == Some(wanted) {
            return;
        }
        let Some(session) = self.session() else {
            return;
        };
        self.pipeline.borrow_mut().meet_requested = Some(wanted);
        let model = self.config.platform_model;
        let worker = self.clone();
        tokio::task::spawn_local(async move {
            let settled = if wanted {
                session.open_meet(model).await
            } else {
                session.close_meet().await
            };
            if let Err(error) = settled {
                log::debug!(error:? = error; "the meet did not settle");
                worker.pipeline.borrow_mut().meet_requested = None;
            }
        });
    }
}

/// The stored peers a batch of hearings may name.
struct HeardPeers<'a> {
    by_address: HashMap<&'a str, &'a MobileStoredNodeRecord>,
    /// By node hint; `None` where two peers share it.
    by_hint: HashMap<[u8; 3], Option<&'a MobileStoredNodeRecord>>,
}

impl<'a> HeardPeers<'a> {
    fn new(nodes: &'a [MobileStoredNodeRecord]) -> Self {
        let mut by_hint = HashMap::new();
        for node in nodes {
            let Some(hint) = node_hint(&node.public_address) else {
                continue;
            };
            by_hint
                .entry(hint)
                .and_modify(|found| *found = None)
                .or_insert(Some(node));
        }
        Self {
            by_address: nodes
                .iter()
                .map(|node| (node.public_address.as_str(), node))
                .collect(),
            by_hint,
        }
    }

    /// The peer a hearing names: by its full address, or by a node hint
    /// exactly one stored peer has. Nothing is stored for a hearing that
    /// names no one.
    fn resolve(&self, hearing: &MobileMeshPeerHeardRecord) -> Option<&'a MobileStoredNodeRecord> {
        if let Some(address) = &hearing.peer_address {
            return self.by_address.get(address.as_str()).copied();
        }
        let hint: [u8; 3] = hearing.node_hint.as_deref()?.try_into().ok()?;
        self.by_hint.get(&hint).copied().flatten()
    }
}

/// The node hint of a stored address.
fn node_hint(address: &str) -> Option<[u8; 3]> {
    let key: [u8; 32] = crate::public_identity_bytes(address.to_owned())
        .ok()?
        .try_into()
        .ok()?;
    Some(NodeHint::from_public_key(&umsh_core::PublicKey(key)).0)
}

/// Which conversations may notify, for one batch.
#[derive(Default)]
struct Mutes {
    /// By conversation address: the channel, and whether it may notify.
    channels: BTreeMap<String, (String, bool)>,
    /// By peer address. A conversation with no row may notify.
    direct: BTreeMap<String, bool>,
}

impl Mutes {
    /// Whether `conversation` may notify, and the channel it is.
    fn allows(&self, conversation: &str) -> Option<Option<String>> {
        if conversation.starts_with(CHANNEL_ADDRESS_PREFIX) {
            let (channel_id, enabled) = self.channels.get(conversation)?;
            enabled.then(|| Some(channel_id.clone()))
        } else {
            self.direct
                .get(conversation)
                .copied()
                .unwrap_or(true)
                .then_some(None)
        }
    }

    fn delivery_failure(
        &self,
        failure: MobileStoredChatDeliveryFailureRecord,
    ) -> Option<MobileNotificationEventRecord> {
        let channel_id = self.allows(&failure.conversation_address)?;
        Some(MobileNotificationEventRecord::DeliveryFailure {
            conversation: failure.conversation_address,
            channel_id,
            body: failure.body,
            undelivered: failure.undelivered,
        })
    }

    /// Messages and reactions, in arrival order: silent tests left out,
    /// several in one conversation told once as a summary, muted
    /// conversations told nothing.
    fn arrivals(
        &self,
        notifications: Vec<MobileChatNotificationRecord>,
    ) -> Vec<MobileNotificationEventRecord> {
        let subjects: Vec<_> = notifications
            .into_iter()
            .filter_map(|notification| match notification {
                MobileChatNotificationRecord::Message { target } => {
                    (!target.silent).then_some(Subject {
                        conversation: target.conversation_address,
                        sender_address: target.sender_address,
                        sender_handle: target.sender_handle,
                        sender_hint: target.sender_hint,
                        body: target.body,
                        is_status: target.is_status,
                        reaction: None,
                    })
                }
                // A reaction is never a test.
                MobileChatNotificationRecord::Reaction { target } => Some(Subject {
                    conversation: target.conversation_address,
                    sender_address: target.sender_address,
                    sender_handle: target.sender_handle,
                    sender_hint: target.sender_hint,
                    body: target.body.clone(),
                    is_status: false,
                    reaction: Some(MobileNotificationReactionRecord {
                        token: target.body,
                        target_body: target.target_body,
                    }),
                }),
            })
            .collect();
        let mut counts: HashMap<String, u32> = HashMap::new();
        for subject in &subjects {
            *counts.entry(subject.conversation.clone()).or_default() += 1;
        }
        let mut summarized = HashSet::new();
        let mut events = Vec::new();
        for subject in subjects {
            let count = counts[&subject.conversation];
            let Some(channel_id) = self.allows(&subject.conversation) else {
                continue;
            };
            if count > 1 {
                if summarized.insert(subject.conversation.clone()) {
                    events.push(MobileNotificationEventRecord::Summary {
                        conversation: subject.conversation,
                        channel_id,
                        count,
                    });
                }
                continue;
            }
            events.push(MobileNotificationEventRecord::Message {
                conversation: subject.conversation,
                channel_id,
                sender_address: subject.sender_address,
                sender_handle: subject.sender_handle,
                sender_hint: subject
                    .sender_hint
                    .and_then(|hint| <[u8; 3]>::try_from(hint).ok())
                    .map(|hint| NodeHint(hint).to_string()),
                body: subject.body,
                is_status: subject.is_status,
                reaction: subject.reaction,
            });
        }
        events
    }
}

struct Subject {
    conversation: String,
    sender_address: Option<String>,
    sender_handle: Option<String>,
    sender_hint: Option<Vec<u8>>,
    body: String,
    is_status: bool,
    reaction: Option<MobileNotificationReactionRecord>,
}

/// Whether a link's identity replaces the one stored for its peer: always
/// over none; otherwise only a validly signed bundle with a timestamp,
/// over one with no timestamp or an older one. A link is of unknown age,
/// so an unsigned or undated one never replaces what was heard. The name,
/// kind and payload travel together, so the caller writes all of them or
/// none.
pub(super) fn link_identity_replaces(
    stored: Option<&MobileStoredNodeRecord>,
    link: &NodeUriPreviewRecord,
) -> bool {
    let (Some(identity), Some(_)) = (&link.identity, &link.identity_payload) else {
        return false;
    };
    let Some((address, payload)) = stored.and_then(|node| {
        node.advertisement
            .as_ref()
            .map(|payload| (node.public_address.clone(), payload.clone()))
    }) else {
        return true;
    };
    if identity.signature != IdentitySignatureState::Valid {
        return false;
    }
    let Some(timestamp) = identity.timestamp else {
        return false;
    };
    crate::decode_node_identity(address, payload)
        .ok()
        .and_then(|stored| stored.timestamp)
        .is_none_or(|stored| stored < timestamp)
}

/// What an advertised role is stored as.
pub(super) fn node_kind(role_code: u8) -> MobileStoredNodeKind {
    match role_code {
        1 => MobileStoredNodeKind::Repeater,
        2 => MobileStoredNodeKind::Chat,
        3 => MobileStoredNodeKind::Tracker,
        4 => MobileStoredNodeKind::Sensor,
        5 => MobileStoredNodeKind::Bridge,
        6 => MobileStoredNodeKind::ChatRoom,
        7 => MobileStoredNodeKind::TemporarySession,
        _ => MobileStoredNodeKind::Unknown,
    }
}
