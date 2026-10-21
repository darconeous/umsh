//! What the store hands back, and the changes made to it outside a
//! commit.
//!
//! Records are owned and small: a back end decodes each into its own
//! scratch, and an iterator item cannot borrow from its iterator. Message
//! bodies and drafts, which can run to 1.6 KB, are not in them; they are
//! read apart into the caller's buffer.

use heapless::{String, Vec};
use umsh_core::{ChannelTag, PublicKey, RouterHint};
use umsh_text::engine::{CompletionStatus, DeliveryState, Direction, Presence};
use umsh_text::{ConversationKey, MessageType, REASSEMBLED_BODY_MAX, SenderScope};

use crate::ids::{ChatId, MessageId, PeerId};
use crate::reaction::{Reaction, Reactions};

/// The longest name the store keeps, in octets of UTF-8. A longer one is
/// cut at the last whole character that fits.
pub const NAME_MAX: usize = 32;

/// A name the store keeps.
pub type Name = String<NAME_MAX>;

/// The longest body or draft, in octets: a fully reassembled message.
pub const BODY_MAX: usize = REASSEMBLED_BODY_MAX;

/// The longest advertised identity a peer record keeps: room for a signed
/// one carrying a name, a location, and a timestamp.
pub const IDENTITY_MAX: usize = 128;

/// The most router hints a learned route keeps.
pub const ROUTE_MAX: usize = 16;

/// `text` as a [`Name`], cut at a character boundary.
pub(crate) fn name(text: &str) -> Name {
    let mut end = text.len().min(NAME_MAX);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut name = Name::new();
    let _ = name.push_str(&text[..end]);
    name
}

/// `text` cut to at most `max` octets, at a character boundary.
pub(crate) fn clip(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// One conversation's transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatRecord {
    pub id: ChatId,
    pub conversation: ConversationKey,
    /// A name given to the chat itself. Without one, the chat goes by its
    /// peer's or channel's.
    pub name: Option<Name>,
    pub muted: bool,
    /// Messages that asked to be noticed since the chat was last read.
    pub unread: u32,
    /// When its newest message was kept, in seconds of wall-clock time,
    /// when the time was known.
    pub last_activity: Option<u32>,
    /// A draft is waiting; read it with [`ChatStore::draft`].
    ///
    /// [`ChatStore::draft`]: crate::ChatStore::draft
    pub has_draft: bool,
}

/// What a message's flags say about it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageFlags {
    /// It filled a slot held for it, out of order.
    pub late: bool,
    /// It asked to be noticed.
    pub notify: bool,
    /// Its sender changed it.
    pub edited: bool,
    /// Its sender withdrew it. The record stays, with no body, for as long
    /// as its wire alias does.
    pub deleted: bool,
    /// To go under a session with forward secrecy, as it was sent: its
    /// frames go under one or not at all. Without, they never do.
    pub forward_secret: bool,
}

/// How each fragment of an outbound message fared, as bitmaps over
/// fragment indices. An unfragmented message is fragment 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    pub sent: u16,
    pub acked: u16,
    pub failed: u16,
}

impl Delivery {
    /// Takes the latest word on one fragment. A failed fragment that is
    /// sent again, or acknowledged after all, has not failed.
    pub fn set(&mut self, fragment: Option<u8>, state: DeliveryState) {
        let bit = 1u16 << fragment.unwrap_or(0).min(15);
        match state {
            DeliveryState::Sent => self.sent |= bit,
            DeliveryState::Acked => self.acked |= bit,
            DeliveryState::Failed => self.failed |= bit,
        }
        if state != DeliveryState::Failed {
            self.failed &= !bit;
        }
    }

    /// Whether word is still to come: nothing has failed, a fragment sent
    /// is unacknowledged or none was sent, and, for a `multicast`, which
    /// no acknowledgment follows, nothing was sent yet.
    pub fn awaited(&self, multicast: bool) -> bool {
        let delivered = self.acked != 0 && self.sent & !self.acked == 0;
        self.failed == 0 && !delivered && !(multicast && self.sent != 0)
    }

    /// Fails what was awaited of a message whose frames went with a
    /// session that is gone: each fragment sent but unacknowledged, or the
    /// first when none was sent. Returns whether anything was awaited.
    pub fn interrupt(&mut self, multicast: bool) -> bool {
        if !self.awaited(multicast) {
            return false;
        }
        let open = self.sent & !self.acked;
        self.failed |= if open == 0 { 1 } else { open };
        true
    }

    /// The latest word on one fragment.
    pub fn state(&self, fragment: Option<u8>) -> Option<DeliveryState> {
        let bit = 1u16 << fragment.unwrap_or(0).min(15);
        if self.acked & bit != 0 {
            Some(DeliveryState::Acked)
        } else if self.failed & bit != 0 {
            Some(DeliveryState::Failed)
        } else if self.sent & bit != 0 {
            Some(DeliveryState::Sent)
        } else {
            None
        }
    }
}

/// What the radio said about the frame a message arrived in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkInfo {
    pub rssi_dbm: Option<i16>,
    pub snr_centibels: Option<i16>,
    /// Radio links the frame crossed, the last one into this node
    /// included.
    pub hop_count: Option<u8>,
    /// The frame authenticated its source.
    pub authenticated: bool,
    /// It came under a session with forward secrecy.
    pub forward_secret: bool,
}

/// One message in a chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRecord {
    pub id: MessageId,
    pub chat: ChatId,
    pub direction: Direction,
    pub sender: SenderScope,
    /// The name the sender gave for themself in the message.
    pub sender_handle: Option<Name>,
    /// Its wire ID in its sender's stream, and that stream's epoch.
    pub wire_id: Option<u8>,
    pub epoch: u16,
    pub message_type: MessageType,
    /// The message it replies to or is about, when the store has it.
    pub regarding: Option<MessageId>,
    /// Octets of body; read it with [`ChatStore::body`].
    ///
    /// [`ChatStore::body`]: crate::ChatStore::body
    pub body_len: u16,
    pub bg_color: Option<[u8; 3]>,
    pub text_color: Option<[u8; 3]>,
    pub status: CompletionStatus,
    pub presence: Presence,
    pub flags: MessageFlags,
    pub delivery: Delivery,
    pub link: Option<LinkInfo>,
    /// When it was kept, in seconds of wall-clock time, when the time was
    /// known.
    pub time: Option<u32>,
    pub reactions: Reactions,
}

impl MessageRecord {
    /// The wire coordinates a later reference to it would carry, in
    /// `conversation`.
    pub fn alias(&self, conversation: ConversationKey) -> Option<WireAlias> {
        Some(WireAlias {
            conversation,
            sender: self.sender,
            epoch: Some(self.epoch),
            wire_id: self.wire_id?,
        })
    }
}

/// Someone's latest reaction to a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReactorRecord {
    pub sender: SenderScope,
    /// It is this node's.
    pub mine: bool,
    pub reaction: Reaction,
}

/// A message's coordinates on the wire, by which a reference that has
/// outlived the engine's handles finds it. Wire IDs recycle, so the
/// newest message that matches is the one meant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireAlias {
    pub conversation: ConversationKey,
    pub sender: SenderScope,
    /// The sender's stream epoch, or `None` to match any.
    pub epoch: Option<u16>,
    pub wire_id: u8,
}

/// A change to a chat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatChange<'a> {
    /// Find the chat for `conversation`, making it if there is none. The
    /// chat named alongside is not consulted.
    Open {
        conversation: ConversationKey,
        name: Option<&'a str>,
    },
    Rename(Option<&'a str>),
    Mute(bool),
    /// Everything in it has been seen.
    Read,
    /// Keep, replace, or clear the draft. A draft longer than
    /// [`BODY_MAX`] is cut to fit.
    Draft(Option<&'a str>),
    /// Remove the chat and its messages. Its checkpoint stays.
    Delete,
}

/// A peer the store knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub id: PeerId,
    pub key: PublicKey,
    pub name: Option<Name>,
    /// Its advertised identity, as advertised: the whole payload when it
    /// came signed and fits, else its role and capabilities alone. Either
    /// way it starts with those two.
    pub identity: Vec<u8, IDENTITY_MAX>,
    /// Its name and identity are its own: they came signed by its key, or
    /// in a frame only its key could have sent. Otherwise they are only
    /// what someone else said of it.
    pub linked: bool,
    pub last_heard: Option<u32>,
    /// The learned route back, nearest router first, or `None` without
    /// one. An empty route is a direct link.
    pub route: Option<Vec<RouterHint, ROUTE_MAX>>,
    /// It prefers forward secrecy.
    pub forward_secrecy: bool,
    /// Saved, rather than only heard. Only saved peers stay for good.
    pub saved: bool,
}

/// A change to a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerChange<'a> {
    /// It was heard, at `at`, saying what it says about itself. A peer
    /// not yet known is kept as heard.
    /// A `linked` name and identity replace an unlinked one, but never
    /// the other way round.
    Heard {
        at: Option<u32>,
        name: Option<&'a str>,
        identity: Option<&'a [u8]>,
        linked: bool,
    },
    /// A route back was learned, or the old one is no good.
    Route(Option<&'a [RouterHint]>),
    /// Keep it for good. A peer not yet known is kept as saved.
    Save {
        name: Option<&'a str>,
    },
    /// Back to heard only, which the newest heard peers outlive.
    Unsave,
    Rename(Option<&'a str>),
    ForwardSecrecy(bool),
    /// Forget it. Heard again later, it is a new peer to the store.
    Forget,
}

/// Which peers to list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerFilter {
    All,
    Saved,
    /// Heard and not saved, most recently heard first: what Find searches.
    Heard,
}

/// Who can read a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelAccess {
    /// Anyone who knows its name: the key comes from the name.
    Named,
    /// Those given its key.
    Private,
    /// Anyone: it is not encrypted.
    Clear,
}

/// The channels every node has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinChannel {
    Public,
    Emergency,
}

impl BuiltinChannel {
    /// The name it is shown by.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Emergency => "EMERGENCY",
        }
    }
}

/// A channel the store knows. Its key is security state, kept elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRecord {
    pub tag: ChannelTag,
    pub name: Name,
    pub access: ChannelAccess,
    pub builtin: Option<BuiltinChannel>,
}

/// A change to a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelChange<'a> {
    /// Keep it, or replace what is kept.
    Add {
        name: &'a str,
        access: ChannelAccess,
        builtin: Option<BuiltinChannel>,
    },
    Rename(&'a str),
    Remove,
}

/// What the store holds, and how much of its room that takes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub chats: usize,
    pub messages: usize,
    pub peers: usize,
    pub channels: usize,
    pub archives: usize,
    pub checkpoints: usize,
    /// Octets counted against the quota.
    pub bytes: usize,
    pub quota: usize,
}

/// Why the store could not do what it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The storage did not read or write.
    Io,
    /// What the storage holds does not decode.
    Corrupt,
    /// There is no room, and nothing left to evict.
    Full,
    /// No such chat, message, peer, or channel.
    NotFound,
    /// The caller's buffer is shorter than what it was to hold.
    BufferTooSmall,
    /// The store lost power, and has not been mounted again.
    PoweredOff,
}
