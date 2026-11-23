//! What `MobileAppCore`'s queries answer with.
//!
//! Each record wraps the stored record it maps and adds only what is
//! derived from it: decoded identities, rendered hints, and the peer a
//! hint names. Nothing copied is renamed, so no mapping can drift from the
//! store's. The conversation records list their fields instead, because
//! they replace the row they embed (the node, the channel ID) with its
//! mapped record; their mapping destructures the stored record whole.
//! Display text (names and their fallbacks, labels) is native.

use super::chat::{MobileAppResent, MobileReaction};
use crate::RepeaterHintRecord;
use crate::meet::MobileMeetStateRecord;
use crate::radio_driver::MobileRadioStateRecord;
use crate::store::{
    MobileStoredChannelRecord, MobileStoredChatMessageRecord,
    MobileStoredConversationPreviewRecord, MobileStoredNodeRecord,
    MobileStoredPeerRepeaterEntryRecord,
};
use crate::{ChannelPreviewRecord, NodeIdentityRecord, PublicIdentityRecord};

/// Where a core is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAppLifecycle {
    /// Made, and answering queries; no identity is running.
    Idle,
    /// `start` is bringing an identity up.
    Starting,
    /// An identity is running: commands are taken.
    Running,
    /// `erase` is taking the identity down.
    Erasing,
    /// `stop` was called; the worker is finishing.
    Stopping,
    /// Finished. A stopped core answers nothing; another takes its place.
    Stopped,
    /// `start` failed. A fresh unlock is needed to try again.
    Failed { reason: MobileAppStartFailure },
}

/// What a failed `start` could not do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAppStartFailure {
    /// The radio refused this phone's key.
    HostKey,
    /// The mesh session, or its counter store, would not start.
    Session,
    /// The store's start-of-session repairs failed.
    Store,
}

/// How a core is set up for its whole life.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppConfigRecord {
    /// An absolute directory the core keeps its counter reservations in,
    /// and removes on `erase`. Each store has its own.
    pub counter_directory: String,
    /// What this phone reports as its model when it meets another.
    pub platform_model: u16,
}

/// The values a listener reads once when it attaches to a running core.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppStatusRecord {
    pub lifecycle: MobileAppLifecycle,
    /// The attached radio, as the core last heard; `None` with no radio.
    pub radio: Option<MobileRadioStateRecord>,
    /// Addresses whose conversations run with forward secrecy now.
    pub forward_secret_conversations: Vec<String>,
    /// The meet's state; `None` while closed.
    pub meet: Option<MobileMeetStateRecord>,
    /// Whether claimed radios are being revoked now.
    pub revoking_claimed_radios: bool,
    /// Whether the user agreed to `EMERGENCY`'s warning under this owner,
    /// within 24 hours of the last send there.
    pub emergency_certified: bool,
}

/// What changed since the last `poll_changes`. A raised flag says to read
/// that part of `state()` again.
#[derive(Clone, Debug, Default, PartialEq, uniffi::Record)]
pub struct MobileAppChangesRecord {
    /// The latest lifecycle, when it changed.
    pub lifecycle: Option<MobileAppLifecycle>,
    /// The attached radio's latest state, when it changed. `use_radio`
    /// with no radio reports `idle`.
    pub radio: Option<MobileRadioStateRecord>,
    /// Read the peers again, and the conversation lists too: each direct
    /// conversation carries its peer whole.
    pub peers_changed: bool,
    /// Read the channels again, and the conversation lists too: each
    /// channel conversation carries its channel whole.
    pub channels_changed: bool,
    pub conversations_changed: bool,
    /// The whole list, when it changed.
    pub forward_secret_conversations: Option<Vec<String>>,
    /// Conversations whose transcripts changed. Read again the ones shown.
    pub transcripts: Vec<String>,
    /// Any transcript may have changed.
    pub all_transcripts: bool,
    /// What to tell the user, oldest first.
    pub notifications: Vec<MobileNotificationEventRecord>,
    /// Notifications let go of past the newest kept.
    pub notifications_dropped: u64,
    /// `meet` holds the meet's state now; `None` there is closed.
    pub meet_changed: bool,
    pub meet: Option<MobileMeetStateRecord>,
    /// The address of the peer an exchange just recorded, once it is
    /// stored. Read the peers first.
    pub exchanged_peer: Option<String>,
    /// Read `claimed_radios()` and `stranded_radios()` again.
    pub claimed_radios_changed: bool,
    /// Whether claimed radios are being revoked, when that changed.
    pub revoking_claimed_radios: Option<bool>,
    /// Whether the user agreed to `EMERGENCY`'s warning, when that
    /// changed: given, or gone with the owner or 24 hours after the last
    /// send there.
    pub emergency_certified: Option<bool>,
    /// Managed devices whose snapshot changed, by `MobileManagedDevice`
    /// id. Read `snapshot()` again on the ones held.
    #[uniffi(default)]
    pub managed_devices: Vec<u64>,
}

/// What to tell the user. Native code words it, after reading again what
/// the same changes record says changed.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileNotificationEventRecord {
    /// One arrival in a conversation.
    Message {
        conversation: String,
        /// The channel, for a channel conversation.
        channel_id: Option<String>,
        sender_address: Option<String>,
        /// The name the sender attached; unverified.
        sender_handle: Option<String>,
        /// The sender's node hint, rendered.
        sender_hint: Option<String>,
        body: String,
        /// Status text, read as the sender's name followed by the body.
        is_status: bool,
        /// Set for a reaction on one of this phone's messages; `body` is
        /// then the reaction's token.
        reaction: Option<MobileNotificationReactionRecord>,
    },
    /// Several arrivals in one conversation.
    Summary {
        conversation: String,
        channel_id: Option<String>,
        count: u32,
    },
    /// A message of this phone's was given up on.
    DeliveryFailure {
        conversation: String,
        channel_id: Option<String>,
        body: String,
        /// It never went out where the peer could read it, rather than
        /// going out and drawing no acknowledgment.
        undelivered: bool,
    },
    /// A peer the user is watching for was heard.
    PeerHeard { address: String },
}

/// What a reaction was, and what it was on.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileNotificationReactionRecord {
    /// The wire token, such as `<3`.
    pub token: String,
    /// What the token reads as; `None` for a body with nothing in it.
    pub reaction: Option<MobileReaction>,
    pub target_body: String,
}

/// The most notifications a changes record keeps while nothing polls.
const NOTIFICATIONS_KEPT: usize = 64;
/// Past this many, transcripts collapse to all of them.
const TRANSCRIPTS_KEPT: usize = 256;

impl MobileAppChangesRecord {
    /// Every list's flag: what a change of owner raises, since each list
    /// then reads differently.
    pub(super) fn every_list() -> Self {
        Self {
            peers_changed: true,
            channels_changed: true,
            conversations_changed: true,
            all_transcripts: true,
            claimed_radios_changed: true,
            ..Self::default()
        }
    }

    /// Fold a later change into this one.
    pub(super) fn merge(&mut self, later: Self) {
        let Self {
            lifecycle,
            radio,
            peers_changed,
            channels_changed,
            conversations_changed,
            forward_secret_conversations,
            transcripts,
            all_transcripts,
            notifications,
            notifications_dropped,
            meet_changed,
            meet,
            exchanged_peer,
            claimed_radios_changed,
            revoking_claimed_radios,
            emergency_certified,
            managed_devices,
        } = later;
        if lifecycle.is_some() {
            self.lifecycle = lifecycle;
        }
        if radio.is_some() {
            self.radio = radio;
        }
        self.peers_changed |= peers_changed;
        self.channels_changed |= channels_changed;
        self.conversations_changed |= conversations_changed;
        if forward_secret_conversations.is_some() {
            self.forward_secret_conversations = forward_secret_conversations;
        }
        self.all_transcripts |= all_transcripts;
        for address in transcripts {
            if !self.transcripts.contains(&address) {
                self.transcripts.push(address);
            }
        }
        if self.all_transcripts || self.transcripts.len() > TRANSCRIPTS_KEPT {
            self.all_transcripts = true;
            self.transcripts.clear();
        }
        self.notifications.extend(notifications);
        let excess = self.notifications.len().saturating_sub(NOTIFICATIONS_KEPT);
        self.notifications.drain(..excess);
        self.notifications_dropped = self
            .notifications_dropped
            .saturating_add(notifications_dropped)
            .saturating_add(excess as u64);
        if meet_changed {
            self.meet_changed = true;
            self.meet = meet;
        }
        if exchanged_peer.is_some() {
            self.exchanged_peer = exchanged_peer;
        }
        self.claimed_radios_changed |= claimed_radios_changed;
        if revoking_claimed_radios.is_some() {
            self.revoking_claimed_radios = revoking_claimed_radios;
        }
        if emergency_certified.is_some() {
            self.emergency_certified = emergency_certified;
        }
        // Uncapped: no more than the live managed devices.
        for device in managed_devices {
            if !self.managed_devices.contains(&device) {
                self.managed_devices.push(device);
            }
        }
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
    /// Whether it plausibly forwards: what it advertised when that decodes,
    /// else a stored repeater or bridge.
    #[uniffi(default)]
    pub likely_repeater: bool,
    /// Its advertised identity may be attributed to it: signed and valid,
    /// or unsigned in a frame the MAC authenticated. `false` without one.
    #[uniffi(default)]
    pub advertisement_attributable: bool,
    /// What it advertised says about forwarding, for steering an ask.
    pub repeater_evidence: MobileRepeaterEvidence,
    /// Its two-byte repeater hint, rendered.
    pub repeater_hint: RepeaterHintRecord,
}

/// What is known of whether a peer forwards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum MobileRepeaterEvidence {
    /// It advertised forwarding, or is stored as a repeater or bridge.
    Yes,
    /// Nothing says what it is.
    #[default]
    Unknown,
    /// It advertised, or is stored as, something that does not forward.
    No,
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
    /// The channel is `EMERGENCY` and its warning has not been agreed to
    /// under this owner: every transmission here is refused until it is.
    #[uniffi(default)]
    pub needs_emergency_agreement: bool,
}

/// One neighbor a repeater reported.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppRepeaterNeighborRecord {
    pub entry: MobileStoredPeerRepeaterEntryRecord,
    /// A three-byte hint rendered as a node hint, a longer or shorter one
    /// of at least two bytes as the repeater hint of its first two; `None`
    /// otherwise.
    pub hint_text: Option<String>,
    /// The peer the hint names, when it names one.
    pub peer_address: Option<String>,
}

/// A neighbor, with the address of the repeater that reported it.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppNeighborReportRecord {
    pub reporter_address: String,
    pub neighbor: MobileAppRepeaterNeighborRecord,
}

/// What a repeater last said about its neighbors.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileAppRepeaterListingRecord {
    /// In the order the repeater listed them.
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
    /// The repeater hint, rendered; `None` when it is not two bytes.
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
    /// What each of `stored.reactions` reads as, in the same order; `None`
    /// for a body with nothing in it.
    pub reactions: Vec<Option<MobileReaction>>,
    /// Until when a message of ours, not deleted, may be edited or resent
    /// in place; `None` for any other.
    pub revise_until_ms: Option<i64>,
    /// What the row offers now. Read again once `revise_until_ms` passes.
    #[uniffi(default)]
    pub actions: MobileMessageActionsRecord,
}

/// What may be done to one message, as the core would take it when it was
/// read. Copying, details and the original text are always native's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobileMessageActionsRecord {
    #[uniffi(default)]
    pub edit: bool,
    #[uniffi(default)]
    pub delete: bool,
    /// How a resend would first go; `None` when it cannot be resent.
    /// `InPlace` may still end `AsNew`: `resend`'s answer says which.
    #[uniffi(default)]
    pub resend: Option<MobileAppResent>,
    #[uniffi(default)]
    pub react: bool,
    #[uniffi(default)]
    pub reply: bool,
    /// A gap the session may be asked to fill.
    #[uniffi(default)]
    pub request_missing: bool,
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
}

/// A channel just joined.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileAppJoinedChannelRecord {
    pub channel_id: String,
    /// The channel's conversation, when the join opened it.
    pub conversation_address: Option<String>,
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
