//! Stored records to query records: decoding, hint rendering, and naming a
//! hint's peer. Pure functions of what the store returned.

use std::collections::HashMap;

use umsh_core::{NodeHint, PublicKey, RepeaterHint};

use super::chat::{REVISE_WINDOW_MS, is_emergency_channel, message_actions, reaction_from_body};
use super::records::{
    MobileAppChannelConversationRecord, MobileAppChannelRecord, MobileAppDirectConversationRecord,
    MobileAppMessageRecord, MobileAppMessageRepeaterRecord, MobileAppNeighborReportRecord,
    MobileAppPeerRecord, MobileAppPreviewRecord, MobileAppRepeaterListingRecord,
    MobileAppRepeaterNeighborRecord, MobileAppTranscriptPageRecord, MobileRepeaterEvidence,
};
use crate::store::{
    MobileApplicationRecords, MobileStoredChannelConversationRecord, MobileStoredChannelKind,
    MobileStoredChannelRecord, MobileStoredChatMessagePageRecord, MobileStoredChatMessageRecord,
    MobileStoredConversationPreviewRecord, MobileStoredDirectConversationRecord,
    MobileStoredNodeKind, MobileStoredNodeRecord, MobileStoredPeerRepeaterEntryRecord,
    MobileStoredPeerRepeaterListingRecord,
};
use crate::{
    IdentitySignatureState, MobileWellKnownChannel, NodeIdentityRecord, RepeaterHintRecord,
    node_identity_record, public_identity_record,
};

/// A peer, mapped; `None` when its address does not decode, which leaves
/// it out of every list along with its conversations and reports.
pub(super) fn peer(stored: MobileStoredNodeRecord) -> Option<MobileAppPeerRecord> {
    let key = PublicKey(umsh_core::base58::decode(stored.public_address.as_bytes()).ok()?);
    let advertised_identity = stored
        .advertisement
        .as_deref()
        .and_then(|payload| node_identity_record(&key, payload).ok());
    let identity = public_identity_record(&key);
    let repeater_hint = peer_repeater_hint(&identity.hint.bytes)?;
    Some(MobileAppPeerRecord {
        likely_repeater: likely_repeater(
            advertised_identity
                .as_ref()
                .map(|identity| identity.forwards),
            stored.node_kind,
        ),
        advertisement_attributable: advertised_identity.as_ref().is_some_and(|identity| {
            attributable(identity.signature, stored.advertisement_authenticated)
        }),
        repeater_evidence: repeater_evidence(advertised_identity.as_ref(), stored.node_kind),
        repeater_hint,
        identity,
        advertised_identity,
        stored,
    })
}

/// Whether an advertised identity may be attributed to the key it names:
/// a valid signature, or none in a frame the MAC authenticated. A
/// signature that fails never is, however the bundle arrived.
pub(super) fn attributable(signature: IdentitySignatureState, authenticated: bool) -> bool {
    match signature {
        IdentitySignatureState::Valid => true,
        IdentitySignatureState::Unsigned => authenticated,
        IdentitySignatureState::Invalid => false,
    }
}

/// What is known of whether a peer forwards: yes when it is likely to;
/// otherwise unknown when nothing names its role (an advertised role this
/// build has no name for, or none stored), else no.
pub(super) fn repeater_evidence(
    identity: Option<&NodeIdentityRecord>,
    kind: Option<MobileStoredNodeKind>,
) -> MobileRepeaterEvidence {
    if likely_repeater(identity.map(|identity| identity.forwards), kind) {
        return MobileRepeaterEvidence::Yes;
    }
    let unknown = match identity {
        Some(identity) => matches!(
            umsh_node::NodeRole::from_byte(identity.role_code),
            umsh_node::NodeRole::Unspecified | umsh_node::NodeRole::Unknown(_)
        ),
        None => matches!(kind, None | Some(MobileStoredNodeKind::Unknown)),
    };
    if unknown {
        MobileRepeaterEvidence::Unknown
    } else {
        MobileRepeaterEvidence::No
    }
}

/// A node hint's text, for exactly three bytes.
pub(super) fn node_hint_text(bytes: &[u8]) -> Option<String> {
    Some(NodeHint(bytes.try_into().ok()?).to_string())
}

/// A repeater hint's text, for exactly two bytes.
pub(super) fn repeater_hint_text(bytes: &[u8]) -> Option<String> {
    Some(RepeaterHint(bytes.try_into().ok()?).to_string())
}

/// A peer's own repeater hint: the first two bytes of its key, or of its
/// node hint, which a repeater carrying its traffic puts on the wire.
pub(super) fn peer_repeater_hint(key_or_hint: &[u8]) -> Option<RepeaterHintRecord> {
    let bytes = key_or_hint.get(..2)?.to_vec();
    Some(RepeaterHintRecord {
        text: repeater_hint_text(&bytes)?,
        bytes,
    })
}

/// A neighbor's hint, as a node hint when it is one, else as the repeater
/// hint of its first two bytes.
fn neighbor_hint_text(bytes: &[u8]) -> Option<String> {
    node_hint_text(bytes).or_else(|| repeater_hint_text(bytes.get(..2)?))
}

/// Whether a peer is likely to forward, from what it advertised when that
/// decodes, else from the role stored for it.
fn likely_repeater(forwards: Option<bool>, kind: Option<MobileStoredNodeKind>) -> bool {
    forwards.unwrap_or(matches!(
        kind,
        Some(MobileStoredNodeKind::Repeater | MobileStoredNodeKind::Bridge)
    ))
}

/// The peers a hint can name, with what naming needs.
pub(super) struct PeerIndex {
    peers: Vec<Indexed>,
}

struct Indexed {
    address: String,
    hint: [u8; 3],
    likely_repeater: Evidence,
}

/// Whether a peer is likely to forward, settled or still to be decoded.
/// Only a peer whose hint matches is ever asked, so a transcript page does
/// not decode every stored advertisement to name its few repeaters.
enum Evidence {
    Settled(bool),
    Stored {
        advertisement: Vec<u8>,
        kind: Option<MobileStoredNodeKind>,
    },
}

impl Evidence {
    fn likely_repeater(&self) -> bool {
        match self {
            Self::Settled(value) => *value,
            Self::Stored {
                advertisement,
                kind,
            } => likely_repeater(
                umsh_node::NodeIdentityPayload::from_bytes(advertisement)
                    .ok()
                    .map(|identity| umsh_node::forwards(identity.role, identity.capabilities)),
                *kind,
            ),
        }
    }
}

impl PeerIndex {
    /// Over mapped peers.
    pub(super) fn of_peers<'a>(peers: impl IntoIterator<Item = &'a MobileAppPeerRecord>) -> Self {
        Self {
            peers: peers
                .into_iter()
                .filter_map(|peer| {
                    Some(Indexed {
                        address: peer.identity.canonical_address.clone(),
                        hint: peer.identity.hint.bytes.as_slice().try_into().ok()?,
                        likely_repeater: Evidence::Settled(peer.likely_repeater),
                    })
                })
                .collect(),
        }
    }

    /// Over stored rows, leaving out those whose address does not decode,
    /// as the lists do.
    pub(super) fn of_nodes(nodes: Vec<MobileStoredNodeRecord>) -> Self {
        Self {
            peers: nodes
                .into_iter()
                .filter_map(|node| {
                    let key =
                        PublicKey(umsh_core::base58::decode(node.public_address.as_bytes()).ok()?);
                    let identity = public_identity_record(&key);
                    Some(Indexed {
                        hint: identity.hint.bytes.as_slice().try_into().ok()?,
                        address: identity.canonical_address,
                        likely_repeater: match node.advertisement {
                            Some(advertisement) => Evidence::Stored {
                                advertisement,
                                kind: node.node_kind,
                            },
                            None => Evidence::Settled(likely_repeater(None, node.node_kind)),
                        },
                    })
                })
                .collect(),
        }
    }

    /// The peer `hint` names: among those whose node hint starts with it,
    /// the one likely to forward, else the only one, else none.
    pub(super) fn named(&self, hint: &[u8]) -> Option<String> {
        let candidates: Vec<&Indexed> = self
            .peers
            .iter()
            .filter(|peer| peer.hint.starts_with(hint))
            .collect();
        let mut repeaters = candidates
            .iter()
            .filter(|peer| peer.likely_repeater.likely_repeater());
        let chosen = match (repeaters.next(), repeaters.next()) {
            (Some(only), None) => Some(*only),
            _ => match candidates.as_slice() {
                [only] => Some(*only),
                _ => None,
            },
        };
        chosen.map(|peer| peer.address.clone())
    }
}

pub(super) fn neighbor(
    entry: MobileStoredPeerRepeaterEntryRecord,
    peers: &PeerIndex,
) -> MobileAppRepeaterNeighborRecord {
    MobileAppRepeaterNeighborRecord {
        hint_text: neighbor_hint_text(&entry.hint),
        peer_address: peers.named(&entry.hint),
        entry,
    }
}

pub(super) fn listing(
    stored: MobileStoredPeerRepeaterListingRecord,
    peers: &PeerIndex,
) -> MobileAppRepeaterListingRecord {
    MobileAppRepeaterListingRecord {
        entries: stored
            .entries
            .into_iter()
            .map(|entry| neighbor(entry, peers))
            .collect(),
        total: stored.total,
        next_cursor: stored.next_cursor,
        as_of_ms: stored.as_of_ms,
    }
}

fn preview(stored: MobileStoredConversationPreviewRecord) -> MobileAppPreviewRecord {
    MobileAppPreviewRecord {
        sender_node_hint: stored.sender_hint.as_deref().and_then(node_hint_text),
        stored,
    }
}

/// The lists of `state()`, from one read of the store. Without peers (a
/// conversations-only read) each conversation's peer comes from the row
/// the conversation carries, and there are no reports.
pub(super) struct Lists {
    pub peers: Option<Vec<MobileAppPeerRecord>>,
    pub channels: Vec<MobileAppChannelRecord>,
    pub direct_conversations: Vec<MobileAppDirectConversationRecord>,
    pub channel_conversations: Vec<MobileAppChannelConversationRecord>,
    pub neighbor_reports: Option<Vec<MobileAppNeighborReportRecord>>,
}

/// Where a channel sorts in the channel list: `Public`, then `EMERGENCY`,
/// then every other channel. Only a built-in row ranks as a built-in.
fn builtin_rank(channel: &MobileStoredChannelRecord) -> u8 {
    if channel.kind != MobileStoredChannelKind::Builtin {
        return 2;
    }
    match crate::well_known_channel(channel.canonical_name.clone()) {
        Some(known) => match known.channel {
            MobileWellKnownChannel::Public => 0,
            MobileWellKnownChannel::Emergency => 1,
        },
        None => 2,
    }
}

/// `certified` is whether the user agreed to `EMERGENCY`'s warning under
/// this owner.
pub(super) fn lists(
    records: MobileApplicationRecords,
    conversations_only: bool,
    certified: bool,
) -> Lists {
    let MobileApplicationRecords {
        peers,
        channels,
        conversations,
        channel_conversations,
        reports,
    } = records;

    let peers = (!conversations_only).then(|| peers.into_iter().filter_map(peer).collect());
    let neighbor_reports = peers.as_ref().map(|peers: &Vec<MobileAppPeerRecord>| {
        let index = PeerIndex::of_peers(peers);
        let addresses: HashMap<i64, &str> = peers
            .iter()
            .map(|peer| (peer.stored.id, peer.identity.canonical_address.as_str()))
            .collect();
        reports
            .into_iter()
            .filter_map(|report| {
                Some(MobileAppNeighborReportRecord {
                    reporter_address: (*addresses.get(&report.reporter_node_id)?).to_owned(),
                    neighbor: neighbor(report.entry, &index),
                })
            })
            .collect()
    });

    // Destructured whole, here and below, so a field the store adds fails
    // to compile until it is carried.
    let direct_conversations = conversations
        .into_iter()
        .filter_map(|conversation| {
            let MobileStoredDirectConversationRecord {
                id,
                node,
                draft_text,
                last_read_at_ms,
                created_at_ms,
                notifications_enabled,
                last_message,
                unread_count,
            } = conversation;
            Some(MobileAppDirectConversationRecord {
                id,
                peer: peer(node)?,
                draft_text,
                last_read_at_ms,
                created_at_ms,
                notifications_enabled,
                last_message: last_message.map(preview),
                unread_count,
            })
        })
        .collect();

    let addresses: HashMap<&str, &str> = channel_conversations
        .iter()
        .map(|conversation| {
            (
                conversation.channel_id.as_str(),
                conversation.conversation_address.as_str(),
            )
        })
        .collect();
    let mut channels: Vec<MobileAppChannelRecord> = channels
        .into_iter()
        .map(|stored| MobileAppChannelRecord {
            conversation_address: addresses.get(stored.id.as_str()).map(|&a| a.to_owned()),
            stored,
        })
        .collect();
    // Stable, so the store's oldest-first order holds within each rank.
    channels.sort_by_key(|channel| builtin_rank(&channel.stored));

    // A left channel has no key to send with, so its conversation is not
    // listed.
    let joined: HashMap<&str, &MobileAppChannelRecord> = channels
        .iter()
        .filter(|channel| channel.stored.joined_phone)
        .map(|channel| (channel.stored.id.as_str(), channel))
        .collect();
    let channel_conversations = channel_conversations
        .into_iter()
        .filter_map(|conversation| {
            let MobileStoredChannelConversationRecord {
                id,
                channel_id,
                conversation_address,
                draft_text,
                last_read_at_ms,
                created_at_ms,
                last_message,
                unread_count,
            } = conversation;
            let channel = joined.get(channel_id.as_str())?.stored.clone();
            Some(MobileAppChannelConversationRecord {
                id,
                needs_emergency_agreement: !certified && is_emergency_channel(&channel),
                channel,
                conversation_address,
                draft_text,
                last_read_at_ms,
                created_at_ms,
                last_message: last_message.map(preview),
                unread_count,
            })
        })
        .collect();

    Lists {
        peers,
        channels,
        direct_conversations,
        channel_conversations,
        neighbor_reports,
    }
}

/// Whether a page names a repeater, and so needs the peers to name it.
pub(super) fn names_repeaters(page: &MobileStoredChatMessagePageRecord) -> bool {
    page.messages.iter().any(|message| {
        message
            .repeats
            .as_ref()
            .is_some_and(|repeats| !repeats.repeaters.is_empty())
    })
}

/// `now_ms` is the instant the actions are decided at.
pub(super) fn page(
    page: MobileStoredChatMessagePageRecord,
    peers: Option<&PeerIndex>,
    now_ms: i64,
) -> MobileAppTranscriptPageRecord {
    MobileAppTranscriptPageRecord {
        messages: page
            .messages
            .into_iter()
            .map(|stored| message(stored, peers, now_ms))
            .collect(),
        has_older: page.has_older,
        has_newer: page.has_newer,
    }
}

fn message(
    stored: MobileStoredChatMessageRecord,
    peers: Option<&PeerIndex>,
    now_ms: i64,
) -> MobileAppMessageRecord {
    let repeaters = stored
        .repeats
        .iter()
        .flat_map(|repeats| &repeats.repeaters)
        .map(|hint| {
            let hint_text = repeater_hint_text(hint);
            MobileAppMessageRepeaterRecord {
                // A hint that does not render names nobody.
                peer_address: hint_text
                    .is_some()
                    .then(|| peers.and_then(|peers| peers.named(hint)))
                    .flatten(),
                hint_text,
                hint: hint.clone(),
            }
        })
        .collect();
    let reactions = stored
        .reactions
        .iter()
        .map(|reaction| reaction_from_body(&reaction.body))
        .collect();
    let revise_until_ms = (stored.outbound && !stored.is_deleted)
        .then(|| stored.created_at_ms.saturating_add(REVISE_WINDOW_MS));
    MobileAppMessageRecord {
        actions: message_actions(&stored, now_ms),
        reactions,
        revise_until_ms,
        sender_node_hint: stored.sender_hint.as_deref().and_then(node_hint_text),
        quoted_sender_node_hint: stored
            .quote
            .as_ref()
            .and_then(|quote| quote.original.as_ref())
            .and_then(|original| original.sender_hint.as_deref())
            .and_then(node_hint_text),
        repeaters,
        stored,
    }
}
