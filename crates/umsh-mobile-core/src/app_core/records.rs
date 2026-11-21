//! What `MobileAppCore`'s queries answer with.
//!
//! Each record wraps the stored record it maps and adds only what is
//! derived from it: decoded identities, rendered hints, and the peer a
//! hint names. Nothing copied is renamed, so no mapping can drift from the
//! store's. The conversation records list their fields instead, because
//! they replace the row they embed (the node, the channel ID) with its
//! mapped record; their mapping destructures the stored record whole.
//! Display text (names and their fallbacks, labels) is native.

use crate::store::{
    MobileStoredChannelRecord, MobileStoredChatMessageRecord,
    MobileStoredConversationPreviewRecord, MobileStoredNodeRecord,
    MobileStoredPeerRepeaterEntryRecord,
};
use crate::{ChannelPreviewRecord, NodeIdentityRecord, PublicIdentityRecord};

/// Where a core is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAppLifecycle {
    /// Made, and answering queries.
    Idle,
    /// `stop` was called; the worker is finishing.
    Stopping,
    /// Finished. A stopped core answers nothing; another takes its place.
    Stopped,
}

/// The values a listener reads once when it attaches to a running core.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppStatusRecord {
    pub lifecycle: MobileAppLifecycle,
}

/// What changed since the last `poll_changes`. A raised flag says to read
/// that part of `state()` again.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppChangesRecord {
    /// The latest lifecycle, when it changed.
    pub lifecycle: Option<MobileAppLifecycle>,
    pub peers_changed: bool,
    pub channels_changed: bool,
    pub conversations_changed: bool,
}

impl MobileAppChangesRecord {
    /// Fold a later change into this one.
    pub(super) fn merge(&mut self, later: Self) {
        if later.lifecycle.is_some() {
            self.lifecycle = later.lifecycle;
        }
        self.peers_changed |= later.peers_changed;
        self.channels_changed |= later.channels_changed;
        self.conversations_changed |= later.conversations_changed;
    }
}

/// A peer, with its address decoded.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppPeerRecord {
    pub stored: MobileStoredNodeRecord,
    /// The canonical address and the node hint.
    pub identity: PublicIdentityRecord,
    /// The stored advertisement, decoded; `None` when there is none or it
    /// does not decode.
    pub advertised_identity: Option<NodeIdentityRecord>,
}

/// A channel, with the address its conversation is kept under.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppChannelRecord {
    pub stored: MobileStoredChannelRecord,
    /// `None` when the channel has no conversation row.
    pub conversation_address: Option<String>,
}

/// A conversation's newest message, as a list row shows it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppPreviewRecord {
    pub stored: MobileStoredConversationPreviewRecord,
    /// The sender's node hint, rendered; `None` when the message carries
    /// none, or one that is not a node hint.
    pub sender_node_hint: Option<String>,
}

/// A conversation with one peer.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppDirectConversationRecord {
    pub id: i64,
    pub peer: MobileAppPeerRecord,
    pub draft_text: String,
    pub last_read_at_ms: i64,
    pub created_at_ms: i64,
    pub notifications_enabled: bool,
    pub last_message: Option<MobileAppPreviewRecord>,
    pub unread_count: i64,
}

/// A joined channel's group conversation.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppChannelConversationRecord {
    pub id: i64,
    pub channel: MobileStoredChannelRecord,
    pub conversation_address: String,
    pub draft_text: String,
    pub last_read_at_ms: i64,
    pub created_at_ms: i64,
    pub last_message: Option<MobileAppPreviewRecord>,
    pub unread_count: i64,
}

/// One neighbor a router reported.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppRepeaterNeighborRecord {
    pub entry: MobileStoredPeerRepeaterEntryRecord,
    /// A three-byte hint rendered as a node hint, a longer or shorter one
    /// of at least two bytes as the router hint of its first two; `None`
    /// otherwise.
    pub hint_text: Option<String>,
    /// The peer the hint names, when it names one.
    pub peer_address: Option<String>,
}

/// A neighbor, with the address of the router that reported it.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppNeighborReportRecord {
    pub reporter_address: String,
    pub neighbor: MobileAppRepeaterNeighborRecord,
}

/// What a router last said about its neighbors.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppRepeaterListingRecord {
    /// In the order the router listed them.
    pub entries: Vec<MobileAppRepeaterNeighborRecord>,
    pub total: Option<i64>,
    /// Absent once the listing is complete.
    pub next_cursor: Option<Vec<u8>>,
    pub as_of_ms: i64,
}

/// A repeater overheard carrying a message of ours.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppMessageRepeaterRecord {
    pub hint: Vec<u8>,
    /// The router hint, rendered; `None` when it is not two bytes.
    pub hint_text: Option<String>,
    /// The peer the hint names, when it names one.
    pub peer_address: Option<String>,
}

/// One message of a transcript.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppMessageRecord {
    pub stored: MobileStoredChatMessageRecord,
    /// The sender's node hint, rendered.
    pub sender_node_hint: Option<String>,
    /// The quoted message's sender's node hint, rendered.
    pub quoted_sender_node_hint: Option<String>,
    /// `stored.repeats`' repeaters, in the same order.
    pub repeaters: Vec<MobileAppMessageRepeaterRecord>,
}

/// One slice of a transcript, oldest first. The flags say whether storage
/// holds more beyond it in either direction.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppTranscriptPageRecord {
    pub messages: Vec<MobileAppMessageRecord>,
    pub has_older: bool,
    pub has_newer: bool,
}

/// Everything the lists show for the owner.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppStateRecord {
    /// Store order. `None` in a conversations-only answer, which leaves
    /// whatever was last read in place.
    pub peers: Option<Vec<MobileAppPeerRecord>>,
    /// Oldest first.
    pub channels: Vec<MobileAppChannelRecord>,
    /// Most recent first. A conversation whose peer's address does not
    /// decode is left out.
    pub direct_conversations: Vec<MobileAppDirectConversationRecord>,
    /// Most recent first; only those of joined channels.
    pub channel_conversations: Vec<MobileAppChannelConversationRecord>,
    /// `None` in a conversations-only answer.
    pub neighbor_reports: Option<Vec<MobileAppNeighborReportRecord>>,
    /// The name the owner advertises, when it set one.
    pub advertised_name: Option<String>,
    /// Identifiers of channels on the attached radio that no stored channel
    /// derives.
    pub unknown_device_channels: Vec<Vec<u8>>,
}

/// A channel about to be joined.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppChannelPreviewRecord {
    pub preview: ChannelPreviewRecord,
    /// The stored channel with the same key, when there is one.
    pub existing: Option<MobileStoredChannelRecord>,
    /// Another stored channel called what this one is called, ignoring case.
    pub name_conflict: Option<MobileStoredChannelRecord>,
}
