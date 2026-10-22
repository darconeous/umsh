//! The suite every [`ChatStore`] back end passes.
//!
//! It drives the real text engine, and a second engine as the peer, so
//! every batch it commits is one the engine produced. A back end supplies
//! a [`Harness`]—how to make an empty store, arm a power cut, and mount
//! again—and runs [`run`], or each check on its own.
//!
//! The power-cut check cuts power after each step of the commit order and
//! holds what survives to the safety table on [`CommitStep`].

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use umsh_core::{ChannelTag, NodeHint, PublicKey, RouterHint};
use umsh_text::engine::sequence::MessageHandle;
use umsh_text::engine::{
    ArchiveKey, ComposeIntent, ComposeRef, DeliveryState, Direction, Engine, EngineConfig,
    MessageMutation, MutationKind, Output, RegardingRef, StreamCheckpoint,
};
use umsh_text::validate::{DeliveryPath, DirectChannelProfile, Envelope};
use umsh_text::{ConversationKey, SenderScope};

use crate::batch::{Batch, CommitStep, Committed, Subject};
use crate::ids::{ChatId, MessageId};
use crate::reaction::{Reacted, Reaction};
use crate::record::{
    ChannelAccess, ChannelChange, ChannelRecord, ChatChange, ChatRecord, LinkInfo, MessageRecord,
    PeerChange, PeerFilter, PeerRecord, ReactorRecord, StoreError, Usage, WireAlias,
};
use crate::store::ChatStore;

/// How the suite reaches a back end.
pub trait Harness {
    type Store: ChatStore;

    /// A new, empty store.
    fn fresh(&mut self) -> Self::Store;

    /// Lose power once `store`'s next commit has finished `step`: nothing
    /// after it reaches storage.
    fn cut_power_after(&mut self, store: &mut Self::Store, step: CommitStep);

    /// Restore power and mount again from what reached storage.
    fn power_on(&mut self, store: &mut Self::Store);
}

/// Every check.
pub fn run<H: Harness>(harness: &mut H) {
    transcript(harness);
    paging(harness);
    delivery(harness);
    interruption(harness);
    wire_aliases(harness);
    reactions(harness);
    edits_and_deletes(harness);
    chats(harness);
    peers(harness);
    channels(harness);
    buffers(harness);
    remount(harness);
    power_cuts(harness);
    device_lists(harness);
    recent_picks(harness);
    erase(harness);
}

// ─── The rig ─────────────────────────────────────────────────────────────

/// This node's key.
pub const LOCAL: PublicKey = PublicKey([0xA5; 32]);
/// The peer's key.
pub const PEER: PublicKey = PublicKey([0x3C; 32]);
/// A channel both are on.
pub const CHANNEL: ChannelTag = ChannelTag([0x7E; 16]);

type TextEngine = Engine<DirectChannelProfile, 4, 24>;

pub(crate) fn direct() -> ConversationKey {
    ConversationKey::Direct { peer: PEER }
}

pub(crate) fn group() -> ConversationKey {
    ConversationKey::ChannelGroup { channel: CHANNEL }
}

/// What one drain of this node's engine committed.
struct Drained {
    result: Result<Committed, StoreError>,
    /// The wire ID of the outbound message the batch inserted, if it did.
    wire: Option<u8>,
    transmissions: Vec<u32>,
}

/// This node's engine and a peer's, and the map from this node's engine
/// handles to the store's IDs that a session keeps.
pub(crate) struct Rig {
    engine: Box<TextEngine>,
    peer: Box<TextEngine>,
    handles: BTreeMap<MessageHandle, MessageId>,
    now_ms: u64,
    time: u32,
    token: u32,
}

impl Rig {
    pub(crate) fn new() -> Self {
        Self {
            engine: Box::new(Engine::new(
                DirectChannelProfile,
                LOCAL,
                EngineConfig::default(),
                7,
            )),
            peer: Box::new(Engine::new(
                DirectChannelProfile,
                PEER,
                EngineConfig::default(),
                9,
            )),
            handles: BTreeMap::new(),
            now_ms: 1_000,
            time: 1_700_000_000,
            token: 0,
        }
    }

    fn tick(&mut self) {
        self.now_ms += 1_000;
        self.time += 1;
        self.token += 1;
    }

    /// A reboot: a new engine, restored from the store's checkpoints, and
    /// a new engine lifetime's handles.
    fn reboot<S: ChatStore>(&mut self, store: &S) {
        *self.engine = Engine::new(DirectChannelProfile, LOCAL, EngineConfig::default(), 11);
        let checkpoints: Vec<StreamCheckpoint> = store.recent_checkpoints(32).collect();
        self.engine.restore(&checkpoints, self.now_ms);
        self.handles.clear();
    }

    /// Drain this node's engine into one batch and commit it.
    fn drain<S: ChatStore>(&mut self, store: &mut S, link: Option<LinkInfo>) -> Drained {
        let handles = &self.handles;
        let resolve = |handle: MessageHandle| handles.get(&handle).copied();
        let mut batch = Batch::new(Some(self.time), &resolve);
        let mut wire = None;
        let mut transmissions = Vec::new();
        while let Some(output) = self.engine.poll_output() {
            match &output {
                Output::Transmit(transmission) => transmissions.push(transmission.transmission_id),
                Output::StoreMessage(MessageMutation {
                    kind:
                        MutationKind::Insert {
                            direction: Direction::Outbound,
                            wire_id,
                            ..
                        },
                    ..
                }) => wire = wire.or(*wire_id),
                _ => {}
            }
            let engine = &self.engine;
            batch.push(&output, |body| engine.body(body), link);
        }
        let result = store.commit(&batch);
        drop(batch);
        if let Ok(committed) = &result {
            self.handles.extend(committed.inserted.iter().copied());
        }
        Drained {
            result,
            wire,
            transmissions,
        }
    }

    /// Compose on this node and commit it.
    fn send<S: ChatStore>(
        &mut self,
        store: &mut S,
        conversation: ConversationKey,
        intent: ComposeIntent<'_>,
    ) -> (MessageHandle, Drained) {
        self.tick();
        let handle = self
            .engine
            .compose(conversation, self.token, intent, self.now_ms)
            .expect("the engine composes it");
        (handle, self.drain(store, None))
    }

    /// The committed transmissions went out and were acknowledged.
    fn acknowledge<S: ChatStore>(&mut self, store: &mut S, drained: &Drained) {
        for &id in &drained.transmissions {
            self.engine
                .transmit_update(id, DeliveryState::Acked, self.now_ms);
        }
        self.drain(store, None)
            .result
            .expect("the acknowledgments commit");
    }

    /// Say `text` in `conversation`, and return the message it became, or
    /// `None` if the store could not keep it or its acknowledgment.
    #[cfg(all(test, feature = "flash"))]
    pub(crate) fn try_say<S: ChatStore>(
        &mut self,
        store: &mut S,
        conversation: ConversationKey,
        text: &str,
    ) -> Option<MessageId> {
        let (handle, drained) = self.send(
            store,
            conversation,
            ComposeIntent::Text {
                body: text,
                status: false,
            },
        );
        let id = drained.result.as_ref().ok()?.id_of(handle)?;
        for &transmission in &drained.transmissions {
            self.engine
                .transmit_update(transmission, DeliveryState::Acked, self.now_ms);
        }
        self.drain(store, None).result.ok()?;
        Some(id)
    }

    /// Say `text` in `conversation`, and return the message it became.
    pub(crate) fn say<S: ChatStore>(
        &mut self,
        store: &mut S,
        conversation: ConversationKey,
        text: &str,
    ) -> (MessageHandle, MessageId) {
        let (handle, drained) = self.send(
            store,
            conversation,
            ComposeIntent::Text {
                body: text,
                status: false,
            },
        );
        let id = drained
            .result
            .as_ref()
            .expect("the message commits")
            .id_of(handle)
            .expect("it was inserted");
        self.acknowledge(store, &drained);
        (handle, id)
    }

    /// The peer composes `intent` in `conversation` and this node hears
    /// it. Returns the peer's handle and what this node committed.
    fn hear<S: ChatStore>(
        &mut self,
        store: &mut S,
        conversation: ConversationKey,
        intent: ComposeIntent<'_>,
    ) -> (MessageHandle, Committed) {
        self.tick();
        let (theirs, envelope) = match conversation {
            ConversationKey::ChannelGroup { channel } => (
                ConversationKey::ChannelGroup { channel },
                Envelope {
                    path: DeliveryPath::Multicast,
                    conversation,
                    sender: SenderScope::ClaimedMember(NodeHint([PEER.0[0], PEER.0[1], PEER.0[2]])),
                },
            ),
            _ => (
                ConversationKey::Direct { peer: LOCAL },
                Envelope {
                    path: DeliveryPath::Unicast,
                    conversation,
                    sender: SenderScope::Peer(PEER),
                },
            ),
        };
        let handle = self
            .peer
            .compose(theirs, self.token, intent, self.now_ms)
            .expect("the peer composes it");
        let mut payloads = Vec::new();
        let mut sent = Vec::new();
        while let Some(output) = self.peer.poll_output() {
            if let Output::Transmit(transmission) = output {
                sent.push(transmission.transmission_id);
                payloads.push(transmission.payload.to_vec());
            }
        }
        for id in sent {
            self.peer
                .transmit_update(id, DeliveryState::Acked, self.now_ms);
        }
        while self.peer.poll_output().is_some() {}
        for payload in payloads {
            self.engine
                .receive(&envelope, Some(PEER), &payload, self.now_ms)
                .expect("this node takes it");
        }
        let link = LinkInfo {
            rssi_dbm: Some(-91),
            snr_centibels: Some(55),
            hop_count: Some(1),
            authenticated: true,
            forward_secret: false,
        };
        let committed = self
            .drain(store, Some(link))
            .result
            .expect("what was heard commits");
        (handle, committed)
    }

    fn hear_text<S: ChatStore>(
        &mut self,
        store: &mut S,
        conversation: ConversationKey,
        text: &str,
    ) -> (MessageHandle, MessageHandle, MessageId) {
        let (theirs, committed) = self.hear(
            store,
            conversation,
            ComposeIntent::Text {
                body: text,
                status: false,
            },
        );
        let (ours, id) = committed.inserted[0];
        (theirs, ours, id)
    }
}

// ─── Readers ─────────────────────────────────────────────────────────────

fn body<S: ChatStore>(store: &S, id: MessageId) -> String {
    let mut buf = [0u8; crate::record::BODY_MAX];
    store
        .body(id, &mut buf)
        .expect("the body reads")
        .expect("the message is kept")
        .into()
}

fn bodies<S: ChatStore>(store: &S, chat: ChatId) -> Vec<String> {
    store
        .messages(chat, None)
        .map(|record| body(store, record.expect("the record reads").id))
        .collect()
}

pub(crate) fn record<S: ChatStore>(store: &S, id: MessageId) -> MessageRecord {
    store
        .message(id)
        .expect("the record reads")
        .expect("the message is kept")
}

pub(crate) fn archived<S: ChatStore>(
    store: &S,
    conversation: ConversationKey,
    wire: u8,
) -> Option<Vec<u8>> {
    let mut buf = [0u8; umsh_text::engine::MAX_FRAME];
    let key = ArchiveKey {
        conversation,
        message_id: wire,
        fragment: None,
    };
    store
        .archive(&key, &mut buf)
        .expect("the archive reads")
        .map(<[u8]>::to_vec)
}

/// Everything a store shows, for comparing across a remount.
#[derive(Debug, PartialEq)]
struct Snapshot {
    chats: Vec<ChatRecord>,
    messages: Vec<(MessageRecord, String)>,
    drafts: Vec<Option<String>>,
    peers: Vec<PeerRecord>,
    heard: Vec<PeerRecord>,
    channels: Vec<ChannelRecord>,
    checkpoints: Vec<StreamCheckpoint>,
    usage: Usage,
}

fn snapshot<S: ChatStore>(store: &S) -> Snapshot {
    let chats: Vec<ChatRecord> = store.chats().map(Result::unwrap).collect();
    let mut messages = Vec::new();
    let mut drafts = Vec::new();
    for chat in &chats {
        for record in store.messages(chat.id, None) {
            let record = record.unwrap();
            let text = body(store, record.id);
            messages.push((record, text));
        }
        let mut buf = [0u8; crate::record::BODY_MAX];
        drafts.push(store.draft(chat.id, &mut buf).unwrap().map(String::from));
    }
    Snapshot {
        chats,
        messages,
        drafts,
        peers: store.peers(PeerFilter::All).map(Result::unwrap).collect(),
        heard: store.peers(PeerFilter::Heard).map(Result::unwrap).collect(),
        channels: store.channels().map(Result::unwrap).collect(),
        checkpoints: store.recent_checkpoints(usize::MAX).collect(),
        usage: store.usage(),
    }
}

// ─── The checks ──────────────────────────────────────────────────────────

/// Messages go into their chat, newest first, as they were said and
/// heard.
pub fn transcript<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, one) = rig.say(&mut store, direct(), "one");
    let (_, _, two) = rig.hear_text(&mut store, direct(), "two");
    let (_, three) = rig.say(&mut store, direct(), "three");
    assert!(one < two && two < three, "identifiers count up");

    let chat = store.chat_for(&direct()).expect("the chat was made");
    assert_eq!(bodies(&store, chat), ["three", "two", "one"]);
    let heard = record(&store, two);
    assert_eq!(heard.chat, chat);
    assert_eq!(heard.direction, Direction::Inbound);
    assert_eq!(heard.sender, SenderScope::Peer(PEER));
    assert_eq!(heard.link.and_then(|link| link.rssi_dbm), Some(-91));
    assert_eq!(heard.time, Some(rig.time - 1));
    assert_eq!(record(&store, one).direction, Direction::Outbound);

    let listed = store.chats().next().unwrap().unwrap();
    assert_eq!(listed.id, chat);
    assert_eq!(listed.unread, 1, "what was heard asked to be noticed");
    store.update_chat(chat, ChatChange::Read).unwrap();
    assert_eq!(store.chats().next().unwrap().unwrap().unread, 0);
}

/// A chat pages back from any message, lazily.
pub fn paging<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let ids: Vec<MessageId> = (0..10)
        .map(|n| rig.say(&mut store, direct(), &alloc::format!("m{n}")).1)
        .collect();
    let chat = store.chat_for(&direct()).unwrap();
    let page: Vec<MessageId> = store
        .messages(chat, Some(ids[6]))
        .take(3)
        .map(|record| record.unwrap().id)
        .collect();
    assert_eq!(page, [ids[5], ids[4], ids[3]]);
    assert_eq!(store.messages(chat, Some(ids[0])).count(), 0);
    assert_eq!(store.messages(ChatId(u32::MAX), None).count(), 0);
}

/// Word on a transmission reaches its message.
pub fn delivery<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, id) = rig.say(&mut store, direct(), "hello");
    assert_eq!(
        record(&store, id).delivery.state(None),
        Some(DeliveryState::Acked)
    );

    // Whether it went under forward secrecy is kept, and kept again.
    let secrecy = |store: &mut H::Store, forward_secret| {
        let resolve = |_| None;
        let mut batch = Batch::new(None, &resolve);
        batch.secrecy(Subject::Kept(id), forward_secret);
        store.commit(&batch).unwrap()
    };
    assert!(!record(&store, id).flags.forward_secret);
    assert_eq!(secrecy(&mut store, true).messages, [id]);
    assert!(secrecy(&mut store, true).messages.is_empty(), "unchanged");
    harness.power_on(&mut store);
    assert!(record(&store, id).flags.forward_secret);
    secrecy(&mut store, false);
    assert!(!record(&store, id).flags.forward_secret);
}

/// A new session fails what the last one left awaited: a direct message
/// sent but unacknowledged, and messages never sent. A channel message
/// once sent, and a direct one acknowledged, are settled.
pub fn interruption<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, delivered) = rig.say(&mut store, direct(), "delivered");
    let mut sent = |store: &mut H::Store, conversation, text| {
        let (handle, drained) = rig.send(
            store,
            conversation,
            ComposeIntent::Text {
                body: text,
                status: false,
            },
        );
        let id = drained.result.as_ref().unwrap().id_of(handle).unwrap();
        for &transmission in &drained.transmissions {
            rig.engine
                .transmit_update(transmission, DeliveryState::Sent, rig.now_ms);
        }
        rig.drain(store, None).result.unwrap();
        id
    };
    let awaiting = sent(&mut store, direct(), "awaiting");
    let broadcast = sent(&mut store, group(), "broadcast");
    let (handle, drained) = rig.send(
        &mut store,
        direct(),
        ComposeIntent::Text {
            body: "unsent",
            status: false,
        },
    );
    let unsent = drained.result.unwrap().id_of(handle).unwrap();

    store.interrupt().unwrap();
    harness.power_on(&mut store);
    let state = |id| record(&store, id).delivery.state(None);
    assert_eq!(state(delivered), Some(DeliveryState::Acked));
    assert_eq!(state(awaiting), Some(DeliveryState::Failed));
    assert_eq!(state(broadcast), Some(DeliveryState::Sent));
    assert_eq!(state(unsent), Some(DeliveryState::Failed));
}

/// A reference that outlives the engine's handles finds the newest
/// message with its wire ID, and a recycled ID's resend material is the
/// newest message's.
pub fn wire_aliases<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, first) = rig.say(&mut store, direct(), "first");
    let alias = record(&store, first).alias(direct()).unwrap();
    assert_eq!(store.resolve_wire(&alias), Some(first));
    assert_eq!(
        store.resolve_wire(&WireAlias {
            epoch: Some(alias.epoch.unwrap().wrapping_add(1)),
            ..alias
        }),
        None,
        "another epoch's message is another message"
    );

    // Around the 8-bit wire ID space and back to the first one's.
    let mut last = first;
    while record(&store, last).wire_id != Some(alias.wire_id) || last == first {
        last = rig.say(&mut store, direct(), "again").1;
    }
    assert_eq!(store.resolve_wire(&alias), Some(last));
    assert_eq!(
        store.resolve_wire(&WireAlias {
            epoch: None,
            ..alias
        }),
        Some(last)
    );
    let payload = archived(&store, direct(), alias.wire_id).unwrap();
    assert!(
        payload.windows(5).any(|window| window == b"again"),
        "the archive holds what was sent last under the ID"
    );
}

/// Reactions fold into the message they are about: the latest from each
/// sender, counted on reading.
pub fn reactions<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, mine) = rig.say(&mut store, direct(), "lunch?");
    let wire = record(&store, mine).wire_id.unwrap();

    let about_mine = |body| ComposeIntent::Reply {
        body,
        regarding: RegardingRef::Wire {
            message_id: wire,
            direction: Direction::Inbound,
            sender_hint: None,
            epoch: None,
        },
        status: true,
    };
    rig.hear(&mut store, direct(), about_mine("<3"));
    let (_, heard_handle, heard) = rig.hear_text(&mut store, direct(), "sure");
    rig.send(
        &mut store,
        direct(),
        ComposeIntent::Reply {
            body: "+1",
            regarding: RegardingRef::Handle(heard_handle),
            status: true,
        },
    );

    let chat = store.chat_for(&direct()).unwrap();
    assert_eq!(
        store.messages(chat, None).count(),
        2,
        "reactions are not messages"
    );
    assert_eq!(
        record(&store, mine).reactions.as_slice(),
        [Reacted {
            reaction: Reaction::Heart,
            count: 1,
            mine: false
        }]
    );
    assert_eq!(
        record(&store, heard).reactions.as_slice(),
        [Reacted {
            reaction: Reaction::ThumbsUp,
            count: 1,
            mine: true
        }]
    );
    // Each is kept with who sent it.
    let theirs: Vec<ReactorRecord> = store.reactors(mine).collect();
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].reaction, Reaction::Heart);
    assert!(!theirs[0].mine);
    assert!(matches!(theirs[0].sender, SenderScope::Peer(_)));
    let ours: Vec<ReactorRecord> = store.reactors(heard).collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0].reaction, Reaction::ThumbsUp);
    assert!(ours[0].mine);

    // The latest from a sender replaces their earlier one, and an empty
    // one withdraws it.
    rig.hear(&mut store, direct(), about_mine("lol"));
    assert_eq!(record(&store, mine).reactions[0].reaction, Reaction::Laugh);
    assert_eq!(store.reactors(mine).count(), 1);
    rig.hear(&mut store, direct(), about_mine(""));
    assert!(record(&store, mine).reactions.is_empty());
    assert_eq!(store.reactors(mine).count(), 0);
}

/// An edit changes its original in place, and its resend material with
/// it; a delete leaves a tombstone that still resolves, and nothing to
/// resend.
pub fn edits_and_deletes<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (handle, id) = rig.say(&mut store, direct(), "see you at 5");
    let wire = record(&store, id).wire_id.unwrap();
    let original = archived(&store, direct(), wire).unwrap();

    rig.send(
        &mut store,
        direct(),
        ComposeIntent::Edit {
            original: ComposeRef::Handle(handle),
            body: "see you at 6",
        },
    );
    assert_eq!(body(&store, id), "see you at 6");
    assert!(record(&store, id).flags.edited);
    let edited = archived(&store, direct(), wire).unwrap();
    assert_ne!(edited, original, "a resend serves the edited message");

    let chat = store.chat_for(&direct()).unwrap();
    rig.send(
        &mut store,
        direct(),
        ComposeIntent::Delete {
            original: ComposeRef::Handle(handle),
        },
    );
    let tombstone = record(&store, id);
    assert!(tombstone.flags.deleted);
    assert_eq!(tombstone.body_len, 0);
    assert_eq!(
        store.resolve_wire(&tombstone.alias(direct()).unwrap()),
        Some(id)
    );
    assert_eq!(archived(&store, direct(), wire), None);
    assert_eq!(store.messages(chat, None).count(), 1);

    // The peer edits what it said.
    let (theirs, _, heard) = rig.hear_text(&mut store, direct(), "on my way");
    rig.hear(
        &mut store,
        direct(),
        ComposeIntent::Edit {
            original: ComposeRef::Handle(theirs),
            body: "running late",
        },
    );
    assert_eq!(body(&store, heard), "running late");
    assert!(record(&store, heard).flags.edited);
}

/// Chats order by activity, keep drafts and names, and are made and
/// removed; a removed chat's checkpoint stays, and its identifier is not
/// given out again.
pub fn chats<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    rig.say(&mut store, direct(), "hi");
    rig.say(&mut store, group(), "hello, all");
    let direct_chat = store.chat_for(&direct()).unwrap();
    let group_chat = store.chat_for(&group()).unwrap();
    let order =
        |store: &H::Store| -> Vec<ChatId> { store.chats().map(|chat| chat.unwrap().id).collect() };
    assert_eq!(order(&store), [group_chat, direct_chat]);
    rig.hear_text(&mut store, direct(), "hey");
    assert_eq!(order(&store), [direct_chat, group_chat]);
    rig.hear_text(&mut store, group(), "hey, you");
    let heard = store.messages(group_chat, None).next().unwrap().unwrap();
    assert!(matches!(heard.sender, SenderScope::ClaimedMember(_)));

    store
        .update_chat(direct_chat, ChatChange::Draft(Some("about tomorrow")))
        .unwrap();
    store
        .update_chat(direct_chat, ChatChange::Mute(true))
        .unwrap();
    store
        .update_chat(direct_chat, ChatChange::Rename(Some("Sam")))
        .unwrap();
    let chat = store
        .chats()
        .map(Result::unwrap)
        .find(|chat| chat.id == direct_chat)
        .unwrap();
    assert!(chat.has_draft && chat.muted);
    assert_eq!(chat.name.as_deref(), Some("Sam"));
    let mut buf = [0u8; 64];
    assert_eq!(
        store.draft(direct_chat, &mut buf).unwrap(),
        Some("about tomorrow")
    );
    store
        .update_chat(direct_chat, ChatChange::Draft(None))
        .unwrap();
    assert_eq!(store.draft(direct_chat, &mut buf).unwrap(), None);

    // Opening a chat with nobody yet said anything makes it once.
    let other = ConversationKey::Direct {
        peer: PublicKey([0x77; 32]),
    };
    let opened = store
        .update_chat(
            ChatId(u32::MAX),
            ChatChange::Open {
                conversation: other,
                name: None,
            },
        )
        .unwrap();
    assert_eq!(store.chat_for(&other), Some(opened));
    assert_eq!(
        store.update_chat(
            ChatId(u32::MAX),
            ChatChange::Open {
                conversation: other,
                name: None
            }
        ),
        Ok(opened)
    );

    let checkpoint = store.checkpoint(&group()).unwrap();
    store.update_chat(group_chat, ChatChange::Delete).unwrap();
    assert_eq!(store.chat_for(&group()), None);
    assert_eq!(store.messages(group_chat, None).count(), 0);
    assert_eq!(store.checkpoint(&group()), Some(checkpoint));
    assert_eq!(
        store.update_chat(group_chat, ChatChange::Read),
        Err(StoreError::NotFound)
    );
    rig.say(&mut store, group(), "back again");
    let again = store.chat_for(&group()).unwrap();
    assert!(
        again > opened,
        "a chat's identifier is never given out again"
    );
}

/// Peers are heard, saved, routed, and forgotten; Find keeps the 32 most
/// recently heard unsaved ones.
pub fn peers<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let key = |n: u8| {
        let mut key = [n; 32];
        key[1] = 0xEE;
        PublicKey(key)
    };
    let heard = |at: u32| PeerChange::Heard {
        at: Some(at),
        name: Some("trail node"),
        identity: Some(&[1, 2, 3]),
        linked: true,
    };

    let saved = store
        .update_peer(
            &key(1),
            PeerChange::Save {
                name: Some("Robin"),
            },
        )
        .unwrap();
    let first = store.update_peer(&key(2), heard(10)).unwrap();
    assert!(first > saved);
    let record = store.peer(&key(2)).unwrap().unwrap();
    assert_eq!(record.name.as_deref(), Some("trail node"));
    assert_eq!(record.identity.as_slice(), [1, 2, 3]);
    assert_eq!(record.last_heard, Some(10));
    assert!(!record.saved);

    // A saved peer keeps the name it was given.
    store.update_peer(&key(1), heard(11)).unwrap();
    assert_eq!(
        store.peer(&key(1)).unwrap().unwrap().name.as_deref(),
        Some("Robin")
    );
    let route = [RouterHint([9, 9]), RouterHint([8, 8])];
    store
        .update_peer(&key(1), PeerChange::Route(Some(&route)))
        .unwrap();
    store
        .update_peer(&key(1), PeerChange::ForwardSecrecy(true))
        .unwrap();
    let record = store.peer(&key(1)).unwrap().unwrap();
    assert_eq!(record.route.as_deref(), Some(&route[..]));
    assert!(record.forward_secrecy);
    assert_eq!(
        store
            .peers_with_hint(NodeHint([1, 0xEE, 1]))
            .collect::<Vec<_>>(),
        [key(1)]
    );
    assert_eq!(
        store.update_peer(&key(99), PeerChange::Route(None)),
        Err(StoreError::NotFound)
    );

    // Someone else's word never replaces the node's own; its own replaces
    // someone else's.
    let said = |name| PeerChange::Heard {
        at: None,
        name: Some(name),
        identity: Some(&[2, 4]),
        linked: false,
    };
    store.update_peer(&key(2), said("impostor")).unwrap();
    let record = store.peer(&key(2)).unwrap().unwrap();
    assert_eq!(record.name.as_deref(), Some("trail node"));
    assert_eq!(record.identity.as_slice(), [1, 2, 3]);
    assert!(record.linked);
    store.update_peer(&key(3), said("Ash")).unwrap();
    let record = store.peer(&key(3)).unwrap().unwrap();
    assert_eq!(record.name.as_deref(), Some("Ash"));
    assert!(!record.linked);
    store.update_peer(&key(3), heard(13)).unwrap();
    let record = store.peer(&key(3)).unwrap().unwrap();
    assert_eq!(record.name.as_deref(), Some("trail node"));
    assert!(record.linked);
    store.update_peer(&key(3), PeerChange::Forget).unwrap();

    // Forgotten, then heard again: a new peer.
    store.update_peer(&key(2), PeerChange::Forget).unwrap();
    assert_eq!(store.peer(&key(2)).unwrap(), None);
    assert!(store.update_peer(&key(2), heard(12)).unwrap() > first);

    // Find keeps the newest 32 heard; the saved peer stays.
    for n in 10..50u8 {
        store
            .update_peer(&key(n), heard(100 + u32::from(n)))
            .unwrap();
    }
    let found: Vec<PublicKey> = store
        .peers(PeerFilter::Heard)
        .map(|peer| peer.unwrap().key)
        .collect();
    assert_eq!(found.len(), 32);
    assert_eq!(found[0], key(49), "most recently heard first");
    assert_eq!(*found.last().unwrap(), key(18));
    assert_eq!(store.peer(&key(17)).unwrap(), None);
    assert_eq!(store.peer(&key(2)).unwrap(), None);
    assert!(store.peer(&key(1)).unwrap().unwrap().saved);
    assert_eq!(store.peers(PeerFilter::Saved).count(), 1);
}

/// Channels are kept by tag, without their keys.
pub fn channels<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    store
        .update_channel(
            &CHANNEL,
            ChannelChange::Add {
                name: "hikers",
                access: ChannelAccess::Private,
                builtin: None,
            },
        )
        .unwrap();
    store
        .update_channel(&CHANNEL, ChannelChange::Rename("ridge hikers"))
        .unwrap();
    let channels: Vec<ChannelRecord> = store.channels().map(Result::unwrap).collect();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].name.as_str(), "ridge hikers");
    assert_eq!(channels[0].access, ChannelAccess::Private);
    store
        .update_channel(&CHANNEL, ChannelChange::Remove)
        .unwrap();
    assert_eq!(store.channels().count(), 0);
    assert_eq!(
        store.update_channel(&CHANNEL, ChannelChange::Rename("gone")),
        Err(StoreError::NotFound)
    );
}

/// Bodies, drafts, and archives go into the caller's buffer, and a buffer
/// too short says so.
pub fn buffers<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, id) = rig.say(&mut store, direct(), "twelve bytes");
    let wire = record(&store, id).wire_id.unwrap();
    let chat = store.chat_for(&direct()).unwrap();
    store
        .update_chat(chat, ChatChange::Draft(Some("a draft")))
        .unwrap();
    let mut short = [0u8; 4];
    assert_eq!(store.body(id, &mut short), Err(StoreError::BufferTooSmall));
    assert_eq!(
        store.draft(chat, &mut short),
        Err(StoreError::BufferTooSmall)
    );
    let key = ArchiveKey {
        conversation: direct(),
        message_id: wire,
        fragment: None,
    };
    assert_eq!(
        store.archive(&key, &mut short),
        Err(StoreError::BufferTooSmall)
    );
    assert_eq!(record(&store, id).body_len, 12);
    assert_eq!(store.body(MessageId(u32::MAX), &mut short), Ok(None));
}

/// Mounting again shows exactly what was there.
pub fn remount<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (handle, _) = rig.say(&mut store, direct(), "one");
    rig.hear_text(&mut store, direct(), "two");
    rig.say(&mut store, group(), "three");
    rig.send(
        &mut store,
        direct(),
        ComposeIntent::Reply {
            body: "<3",
            regarding: RegardingRef::Handle(handle),
            status: true,
        },
    );
    let chat = store.chat_for(&direct()).unwrap();
    store
        .update_chat(chat, ChatChange::Draft(Some("four")))
        .unwrap();
    store
        .update_peer(&PEER, PeerChange::Save { name: Some("Sam") })
        .unwrap();
    store
        .update_peer(
            &PublicKey([0x42; 32]),
            PeerChange::Heard {
                at: Some(5),
                name: Some("Juniper"),
                identity: Some(&[2, 4]),
                linked: true,
            },
        )
        .unwrap();
    store
        .update_channel(
            &CHANNEL,
            ChannelChange::Add {
                name: "hikers",
                access: ChannelAccess::Named,
                builtin: None,
            },
        )
        .unwrap();
    let before = snapshot(&store);
    harness.power_on(&mut store);
    assert_eq!(snapshot(&store), before);
}

/// Power cut after each step of the commit order leaves what the safety
/// table says, for a message and for an edit of one.
pub fn power_cuts<H: Harness>(harness: &mut H) {
    for step in CommitStep::ALL {
        lost_message(harness, step);
        lost_edit(harness, step);
    }
}

fn lost_message<H: Harness>(harness: &mut H, step: CommitStep) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    rig.say(&mut store, direct(), "before");
    harness.cut_power_after(&mut store, step);
    let (_, drained) = rig.send(
        &mut store,
        direct(),
        ComposeIntent::Text {
            body: "lost",
            status: false,
        },
    );
    let wire = drained.wire.expect("the message had a wire ID");
    assert_eq!(
        drained.result.is_ok(),
        step == CommitStep::Transcript,
        "{step:?}: only a commit that finished says so"
    );
    harness.power_on(&mut store);
    rig.reboot(&store);
    let before = snapshot(&store);
    harness.power_on(&mut store);
    assert_eq!(snapshot(&store), before, "{step:?}: mounting is repeatable");

    let chat = store.chat_for(&direct()).unwrap();
    let shown = bodies(&store, chat);
    let resend = archived(&store, direct(), wire);
    match step {
        // One wire ID goes unused, and a resend request for it finds
        // nothing.
        CommitStep::Checkpoint | CommitStep::ArchiveDeletes => {
            assert_eq!(shown, ["before"], "{step:?}");
            assert_eq!(resend, None, "{step:?}");
        }
        // Resend material for a message neither sent nor shown.
        CommitStep::Archives => {
            assert_eq!(shown, ["before"], "{step:?}");
            assert!(resend.is_some(), "{step:?}");
        }
        CommitStep::Transcript => {
            assert_eq!(shown, ["lost", "before"], "{step:?}");
            assert!(resend.is_some(), "{step:?}");
        }
    }
    // Either way, the next message does not reuse the ID.
    assert_eq!(
        store.checkpoint(&direct()).unwrap().next_id,
        wire.wrapping_add(1)
    );
    let (_, after) = rig.say(&mut store, direct(), "after");
    assert_ne!(record(&store, after).wire_id, Some(wire), "{step:?}");
}

fn lost_edit<H: Harness>(harness: &mut H, step: CommitStep) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (handle, id) = rig.say(&mut store, direct(), "at 5");
    let wire = record(&store, id).wire_id.unwrap();
    let original = archived(&store, direct(), wire).unwrap();
    harness.cut_power_after(&mut store, step);
    let (_, drained) = rig.send(
        &mut store,
        direct(),
        ComposeIntent::Edit {
            original: ComposeRef::Handle(handle),
            body: "at 6",
        },
    );
    assert_eq!(
        drained.result.is_ok(),
        step == CommitStep::Transcript,
        "{step:?}"
    );
    harness.power_on(&mut store);
    let resend = archived(&store, direct(), wire);
    let shown = body(&store, id);
    let edited = record(&store, id).flags.edited;
    match step {
        // Nothing of the edit reached storage that changes what is kept.
        CommitStep::Checkpoint => {
            assert_eq!((shown.as_str(), edited), ("at 5", false), "{step:?}");
            assert_eq!(resend.as_deref(), Some(&original[..]), "{step:?}");
        }
        // The original no longer resends: answered Unavailable, never
        // with what the edit superseded.
        CommitStep::ArchiveDeletes => {
            assert_eq!((shown.as_str(), edited), ("at 5", false), "{step:?}");
            assert_eq!(resend, None, "{step:?}");
        }
        // Resend material for an edit neither sent nor shown.
        CommitStep::Archives => {
            assert_eq!((shown.as_str(), edited), ("at 5", false), "{step:?}");
            assert!(
                resend.is_some_and(|payload| payload != original),
                "{step:?}"
            );
        }
        CommitStep::Transcript => {
            assert_eq!((shown.as_str(), edited), ("at 6", true), "{step:?}");
            assert!(
                resend.is_some_and(|payload| payload != original),
                "{step:?}"
            );
        }
    }
}

/// The recent picks are kept beside the chats until replaced or forgotten,
/// and erasing forgets them.
pub fn recent_picks<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut out = [0u8; 64];
    assert_eq!(store.recent_picks(&mut out).unwrap(), None);
    store.keep_recent_picks(Some(b"a\nb")).unwrap();
    harness.power_on(&mut store);
    assert_eq!(store.recent_picks(&mut out).unwrap(), Some(&b"a\nb"[..]));
    assert_eq!(
        store.recent_picks(&mut [0u8; 2]),
        Err(StoreError::BufferTooSmall)
    );
    store.keep_recent_picks(None).unwrap();
    harness.power_on(&mut store);
    assert_eq!(store.recent_picks(&mut out).unwrap(), None);
    store.keep_recent_picks(Some(b"c")).unwrap();
    store.erase().unwrap();
    harness.power_on(&mut store);
    assert_eq!(store.recent_picks(&mut out).unwrap(), None);
}

/// The device's lists are kept beside the chats until replaced or
/// forgotten, and erasing forgets them.
pub fn device_lists<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut out = [0u8; 64];
    assert_eq!(store.device_lists(&mut out).unwrap(), None);
    store.keep_device_lists(Some(&[1, 2, 3])).unwrap();
    harness.power_on(&mut store);
    assert_eq!(store.device_lists(&mut out).unwrap(), Some(&[1, 2, 3][..]));
    assert_eq!(
        store.device_lists(&mut [0u8; 2]),
        Err(StoreError::BufferTooSmall)
    );
    store.keep_device_lists(None).unwrap();
    harness.power_on(&mut store);
    assert_eq!(store.device_lists(&mut out).unwrap(), None);
    store.keep_device_lists(Some(&[4])).unwrap();
    store.erase().unwrap();
    harness.power_on(&mut store);
    assert_eq!(store.device_lists(&mut out).unwrap(), None);
}

/// Erasing forgets everything, and identifiers are still not given out
/// again.
pub fn erase<H: Harness>(harness: &mut H) {
    let mut store = harness.fresh();
    let mut rig = Rig::new();
    let (_, before) = rig.say(&mut store, direct(), "before");
    let chat = store.chat_for(&direct()).unwrap();
    store
        .update_peer(&PEER, PeerChange::Save { name: None })
        .unwrap();
    store.erase().unwrap();
    let usage = store.usage();
    assert_eq!(
        (
            usage.chats,
            usage.messages,
            usage.peers,
            usage.archives,
            usage.checkpoints
        ),
        (0, 0, 0, 0, 0)
    );
    assert_eq!(store.chats().count(), 0);
    assert_eq!(store.message(before).unwrap(), None);
    rig.reboot(&store);
    let (_, after) = rig.say(&mut store, direct(), "after");
    assert!(after > before);
    assert!(store.chat_for(&direct()).unwrap() > chat);
}
