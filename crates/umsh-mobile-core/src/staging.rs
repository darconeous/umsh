//! A fabricated mesh, for screenshots and for UI work without a radio.
//!
//! Everything here is invented, but nothing is faked at the presentation
//! layer: staged nodes hold genuine Ed25519 keys and genuine signed identity
//! bundles, so the map, the peer sheets, and the address rendering run the
//! same decode-and-verify path they run against a real radio. The mesh is
//! written through the ordinary store, so a staged screen comes out of the
//! same queries as a real one and cannot flatter a screen that is broken
//! for real users.
//!
//! Keys derive from fixed seeds and every instant counts back from the
//! `now` the caller passes, so a fixed owner and `now` reproduce the same
//! store: the same nodes at the same addresses, the same channels under the
//! same IDs. Always compiled; whether to offer staging is the platform's
//! decision.

mod air;

use std::sync::Arc;

pub use air::{MobileStagingAir, MobileStagingAirError};
use umsh_core::ChannelKey;
use umsh_crypto::{
    Sha256Provider,
    software::{SoftwareIdentity, SoftwareSha256},
};
use umsh_node::NodeCapabilities;

use crate::mobile_chat::hex;
use crate::secret_vault::{SecretVault, SecretVaultError};
use crate::store::{
    MobileAppStore, MobilePeerUpsertRecord, MobileStagedChatMessageRecord,
    MobileStagedChatReactionRecord, MobileStagedChatRegarding, MobileStoreError,
    MobileStoredChannelKind, MobileStoredChannelRecord, MobileStoredChatDeliveryState,
    MobileStoredChatReceptionRecord, MobileStoredNodeKind,
};
use crate::{NodeIdentityProfileRecord, public_identity_record, signed_node_identity_bundle};

/// Why the staged mesh could not be written.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileStagingError {
    Store { error: MobileStoreError },
    Vault { error: SecretVaultError },
}

impl std::fmt::Display for MobileStagingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store { error } => error.fmt(formatter),
            Self::Vault { error } => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MobileStagingError {}

impl From<MobileStoreError> for MobileStagingError {
    fn from(error: MobileStoreError) -> Self {
        Self::Store { error }
    }
}

impl From<SecretVaultError> for MobileStagingError {
    fn from(error: SecretVaultError) -> Self {
        Self::Vault { error }
    }
}

/// Write the staged mesh into `store` for `owner_identity_id`, with its
/// channel keys in `vault`.
///
/// Meant for a store of its own, so nothing here can reach a real
/// account's history. Run on every launch of that store: the timeline is
/// written relative to `now_ms`, which is what keeps the newest message
/// reading "4 minutes ago" in a screenshot taken next month. Every write is
/// keyed, so repeating it replaces rather than accumulates. Runs before
/// the identity starts, so it makes the identity's row when there is none.
#[uniffi::export]
pub async fn seed_staging(
    store: Arc<MobileAppStore>,
    vault: Arc<dyn SecretVault>,
    owner_identity_id: String,
    now_ms: i64,
) -> Result<(), MobileStagingError> {
    store.ensure_identity(&owner_identity_id, now_ms)?;
    let seeder = Seeder {
        store: &store,
        vault: vault.as_ref(),
        owner: &owner_identity_id,
        now_ms,
    };
    let mut resolved = Vec::with_capacity(NODES.len());
    for node in NODES {
        resolved.push(seeder.resolve(node).await);
    }
    seeder.write_peers(&resolved)?;
    seeder.write_direct_conversations(&resolved)?;
    seeder.write_channels(&resolved)?;
    Ok(())
}

/// The channel the whole crew coordinates on: a named public channel, so
/// its name derives its key.
const CHANNEL_NAME: &str = "Trail Crew";

/// A private channel beside it, so both kinds of group chat show. Its key
/// is a literal: a private channel *is* its key, so a fresh one per seed
/// would be a different channel every time. Safe in the open because it is
/// fabricated; nothing real is ever encrypted under it.
const PRIVATE_CHANNEL_NAME: &str = "Crew Leads";
const PRIVATE_CHANNEL_KEY: [u8; 32] = [
    0x3B, 0x7A, 0xF1, 0x0C, 0x92, 0x4E, 0xD8, 0x65, 0x11, 0xA3, 0x5F, 0xC7, 0x2D, 0x88, 0xB0, 0x49,
    0xE6, 0x14, 0x7C, 0xA2, 0x53, 0xDF, 0x96, 0x38, 0x0B, 0xE1, 0x6D, 0x74, 0xCA, 0x2F, 0x85, 0x1E,
];

const MINUTE_MS: i64 = 60_000;
const DAY_MS: i64 = 86_400_000;

#[derive(Clone, Copy)]
enum Role {
    Chat,
    Repeater,
    Tracker,
}

impl Role {
    fn node_role(self) -> umsh_node::NodeRole {
        match self {
            Self::Repeater => umsh_node::NodeRole::Repeater,
            Self::Chat => umsh_node::NodeRole::Chat,
            Self::Tracker => umsh_node::NodeRole::Tracker,
        }
    }

    fn code(self) -> u8 {
        self.node_role().as_byte()
    }

    fn kind(self) -> MobileStoredNodeKind {
        match self {
            Self::Repeater => MobileStoredNodeKind::Repeater,
            Self::Chat => MobileStoredNodeKind::Chat,
            Self::Tracker => MobileStoredNodeKind::Tracker,
        }
    }
}

/// The address of the staged peer that speaks to the phone: the first
/// staged node that carries chat.
#[cfg(test)]
pub(crate) fn staged_speaker_address() -> String {
    let node = NODES
        .iter()
        .find(|node| !matches!(node.role, Role::Repeater))
        .expect("a staged node carries chat");
    crate::MobileIdentity::unlock(vec![node.seed; 32])
        .expect("a staged seed unlocks")
        .public_identity()
        .canonical_address
}

/// One node in the staged mesh.
struct Node {
    /// Fills all 32 secret-key bytes, so a node keeps its address, and with
    /// it its avatar color and its place in every sorted list, across seeds.
    seed: u8,
    name: &'static str,
    role: Role,
    capabilities: NodeCapabilities,
    latitude: f64,
    longitude: f64,
    altitude_m: i32,
    saved: bool,
    favorite: bool,
    heard_minutes_ago: i64,
}

/// The cell staged nodes disclose: five bytes is roughly 38 m, what a
/// tracker sharing a useful position reports, and fine enough that markers
/// separate at trail scale.
const LOCATION_PRECISION: u8 = 5;

/// Every node, in the order the roster reads best. They work around
/// Desolation Wilderness, west of Lake Tahoe, so the map has real terrain
/// under the markers. The last two were heard
/// and never saved, which is the ordinary state of most of a mesh.
const NODES: &[Node] = &[
    Node {
        seed: 0x11,
        name: "Maya Ortiz",
        role: Role::Chat,
        capabilities: NodeCapabilities::MOBILE.union(NodeCapabilities::TEXT_MESSAGES),
        latitude: 38.9042,
        longitude: -120.0968,
        altitude_m: 2_180,
        saved: true,
        favorite: true,
        heard_minutes_ago: 4,
    },
    Node {
        seed: 0x22,
        name: "Tallac Ridge",
        role: Role::Repeater,
        // What a fixed repeater advertises: it forwards and exchanges no
        // text of its own.
        capabilities: NodeCapabilities::REPEATER,
        latitude: 38.9061,
        longitude: -120.0983,
        // The high node, which is the point of a ridgeline repeater.
        altitude_m: 2_967,
        saved: true,
        favorite: false,
        heard_minutes_ago: 2,
    },
    Node {
        seed: 0x33,
        name: "Dev Raman",
        role: Role::Tracker,
        capabilities: NodeCapabilities::MOBILE
            .union(NodeCapabilities::TEXT_MESSAGES)
            .union(NodeCapabilities::TELEMETRY),
        latitude: 38.8931,
        longitude: -120.1104,
        altitude_m: 2_243,
        saved: true,
        favorite: true,
        heard_minutes_ago: 11,
    },
    Node {
        seed: 0x44,
        name: "Jules Whitaker",
        role: Role::Chat,
        capabilities: NodeCapabilities::MOBILE.union(NodeCapabilities::TEXT_MESSAGES),
        latitude: 38.8877,
        longitude: -120.0891,
        altitude_m: 2_055,
        saved: true,
        favorite: false,
        heard_minutes_ago: 27,
    },
    Node {
        seed: 0x55,
        name: "Echo Basecamp",
        role: Role::Chat,
        capabilities: NodeCapabilities::TEXT_MESSAGES
            .union(NodeCapabilities::CHAT_ROOM)
            .union(NodeCapabilities::TELEMETRY),
        latitude: 38.8842,
        longitude: -120.0459,
        altitude_m: 2_301,
        saved: true,
        favorite: false,
        heard_minutes_ago: 8,
    },
    Node {
        seed: 0x66,
        name: "Sam Ihara",
        role: Role::Tracker,
        capabilities: NodeCapabilities::MOBILE.union(NodeCapabilities::TEXT_MESSAGES),
        latitude: 38.9138,
        longitude: -120.1187,
        altitude_m: 2_412,
        saved: false,
        favorite: false,
        heard_minutes_ago: 43,
    },
    Node {
        seed: 0x77,
        name: "Glen Alpine Relay",
        role: Role::Repeater,
        capabilities: NodeCapabilities::REPEATER,
        latitude: 38.8759,
        longitude: -120.0827,
        altitude_m: 1_996,
        saved: false,
        favorite: false,
        heard_minutes_ago: 63,
    },
];

/// One staged node, with what the store needs to hold it.
struct Resolved {
    node: &'static Node,
    address: String,
    hint: Vec<u8>,
    bundle: Vec<u8>,
}

struct Seeder<'a> {
    store: &'a MobileAppStore,
    vault: &'a dyn SecretVault,
    owner: &'a str,
    now_ms: i64,
}

impl Seeder<'_> {
    fn ago(&self, minutes: i64) -> i64 {
        self.now_ms - minutes * MINUTE_MS
    }

    /// A staged channel's ID: a UUID (version 8) hashed from the owner and
    /// the key. Fixed for one owner, so a seed reproduces; distinct across
    /// owners, because a channel ID is unique in the whole store and a
    /// store keeps every identity's channels.
    fn channel_id(&self, key: &ChannelKey) -> String {
        let digest =
            SoftwareSha256.hash(&[b"umsh staging channel\0", self.owner.as_bytes(), &key.0]);
        let mut bytes: [u8; 16] = digest[..16].try_into().expect("a digest is 32 bytes");
        bytes[6] = (bytes[6] & 0x0F) | 0x80;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        let hex = hex(&bytes).to_uppercase();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }

    /// When a staged conversation began: its first line. A conversation
    /// created later than its newest message would sort as if it were newer.
    fn started(&self, lines: &[Line]) -> i64 {
        self.ago(lines.iter().map(|line| line.minutes_ago).max().unwrap_or(0))
    }

    /// Give a node its real key and a real signed bundle, claimed when it
    /// was last heard so a peer sheet's two instants agree.
    async fn resolve(&self, node: &'static Node) -> Resolved {
        let identity = SoftwareIdentity::from_secret_bytes(&[node.seed; 32]);
        let public = public_identity_record(umsh_crypto::NodeIdentity::public_key(&identity));
        let claimed_at_s = self.ago(node.heard_minutes_ago).div_euclid(1_000);
        let bundle = signed_node_identity_bundle(
            &identity,
            NodeIdentityProfileRecord {
                role_code: node.role.code(),
                capability_bits: node.capabilities.bits(),
                name: Some(node.name.to_owned()),
                latitude: Some(node.latitude),
                longitude: Some(node.longitude),
                location_precision: Some(LOCATION_PRECISION),
                altitude_m: Some(node.altitude_m),
                timestamp: Some(u32::try_from(claimed_at_s).unwrap_or(0)),
            },
        )
        .await
        .expect("a staged node's profile encodes");
        Resolved {
            node,
            address: public.canonical_address,
            hint: public.hint.bytes,
            bundle,
        }
    }

    fn write_peers(&self, resolved: &[Resolved]) -> Result<(), MobileStoreError> {
        for entry in resolved {
            let heard_at = self.ago(entry.node.heard_minutes_ago);
            self.store.upsert_peer(
                self.owner.to_owned(),
                entry.address.clone(),
                MobilePeerUpsertRecord {
                    alias: None,
                    advertised_name: Some(entry.node.name.to_owned()),
                    is_saved: entry.node.saved,
                    node_kind: Some(entry.node.role.kind()),
                    system_role: None,
                    radio_identifier: None,
                    advertisement: Some(entry.bundle.clone()),
                    // The signature verifies, so this only matters for an
                    // unsigned bundle; set anyway, as a MAC-authenticated
                    // arrival would.
                    advertisement_authenticated: true,
                    advertisement_received_at_ms: Some(heard_at),
                },
            )?;
            self.store
                .touch_last_heard(self.owner.to_owned(), entry.address.clone(), heard_at)?;
            if entry.node.favorite {
                self.store
                    .set_peer_favorite(self.owner.to_owned(), entry.address.clone(), true)?;
            }
        }
        Ok(())
    }

    fn write_direct_conversations(&self, resolved: &[Resolved]) -> Result<(), MobileStoreError> {
        for script in DIRECT_SCRIPTS {
            let Some(peer) = resolved.iter().find(|entry| entry.node.name == script.peer) else {
                continue;
            };
            self.store.ensure_direct_conversation(
                self.owner.to_owned(),
                peer.address.clone(),
                self.started(script.lines),
            )?;
            // A one-to-one transcript names nobody: the conversation already
            // says whose the other voice is. The peer still resolves, so
            // their reactions group as theirs.
            let messages = self.staged_messages(script.lines, false, |name| {
                (name == peer.node.name).then_some(peer)
            });
            self.store.seed_staged_transcript(
                self.owner.to_owned(),
                peer.address.clone(),
                format!("staging-{}", peer.node.seed),
                messages,
            )?;
            if script.mark_read {
                self.store.mark_conversation_read(
                    self.owner.to_owned(),
                    peer.address.clone(),
                    self.now_ms,
                )?;
            }
        }
        Ok(())
    }

    /// Join both staged group chats and fill them.
    fn write_channels(&self, resolved: &[Resolved]) -> Result<(), MobileStagingError> {
        let named =
            umsh_node::Channel::named(CHANNEL_NAME).expect("the staged channel name derives a key");
        self.write_channel(
            StagedChannel {
                name: CHANNEL_NAME,
                kind: MobileStoredChannelKind::Named,
                canonical_name: Some(CHANNEL_NAME.to_ascii_lowercase()),
                key: *named.key(),
                max_flood_hops: None,
                joined_days_ago: 6,
                session_id: "staging-channel",
                lines: CHANNEL_LINES,
            },
            resolved,
        )?;
        self.write_channel(
            StagedChannel {
                name: PRIVATE_CHANNEL_NAME,
                kind: MobileStoredChannelKind::PrivateKey,
                // Nothing about a private channel derives from its name.
                canonical_name: None,
                key: ChannelKey(PRIVATE_CHANNEL_KEY),
                max_flood_hops: Some(3),
                joined_days_ago: 2,
                session_id: "staging-private-channel",
                lines: PRIVATE_CHANNEL_LINES,
            },
            resolved,
        )
    }

    /// Join one channel and fill it, the way a join does: key to the vault
    /// first, row second, so a row is never left without its key.
    fn write_channel(
        &self,
        channel: StagedChannel,
        resolved: &[Resolved],
    ) -> Result<(), MobileStagingError> {
        let key = channel.key.0.to_vec();
        let digest = crate::channel_key_digest(key.clone());
        let address = crate::mobile_chat::channel_address(crate::channel_tag(&channel.key));

        let id = match self.store.channel(self.owner.to_owned(), digest.clone())? {
            // Restated, in case the vault lost it.
            Some(existing) => {
                self.vault.store(existing.id.clone(), key)?;
                existing.id
            }
            None => {
                let id = self.channel_id(&channel.key);
                let joined_at = self.now_ms - channel.joined_days_ago * DAY_MS;
                // What the wire carries; a channel row keeps it as a hint.
                let wire_id = umsh_node::Channel::private(channel.key, "");
                self.vault.store(id.clone(), key)?;
                let inserted = self.store.insert_channel(
                    MobileStoredChannelRecord {
                        id: id.clone(),
                        owner_identity_id: self.owner.to_owned(),
                        kind: channel.kind,
                        canonical_name: channel.canonical_name,
                        name: Some(channel.name.to_owned()),
                        alias: None,
                        channel_id_hex: hex(&wire_id.channel_id().0),
                        tint: crate::channel_tint(&channel.key),
                        region_code: None,
                        max_flood_hops: channel.max_flood_hops,
                        joined_phone: true,
                        joined_device: false,
                        notifications_enabled: true,
                        joined_at_ms: Some(joined_at),
                    },
                    digest,
                    joined_at,
                );
                if let Err(error) = inserted {
                    let _ = self.vault.delete(id);
                    return Err(error.into());
                }
                id
            }
        };

        self.store.ensure_channel_conversation(
            self.owner.to_owned(),
            id,
            address.clone(),
            self.started(channel.lines),
        )?;
        let messages = self.staged_messages(channel.lines, true, |name| {
            resolved.iter().find(|entry| entry.node.name == name)
        });
        self.store.seed_staged_transcript(
            self.owner.to_owned(),
            address,
            channel.session_id.to_owned(),
            messages,
        )?;
        Ok(())
    }

    /// Turn a script into store rows. `resolve` is how a speaker's name
    /// becomes an address and a hint; `named_senders` is whether messages
    /// carry their sender's name, as a group message does.
    fn staged_messages<'r>(
        &self,
        lines: &[Line],
        named_senders: bool,
        resolve: impl Fn(&str) -> Option<&'r Resolved>,
    ) -> Vec<MobileStagedChatMessageRecord> {
        lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let sender = line.speaker.and_then(&resolve);
                let outbound = line.speaker.is_none();
                MobileStagedChatMessageRecord {
                    handle: index as u32 + 1,
                    body: line.body.to_owned(),
                    outbound,
                    created_at_ms: self.ago(line.minutes_ago),
                    sender_address: sender.map(|sender| sender.address.clone()),
                    sender_hint: sender.map(|sender| sender.hint.clone()),
                    sender_handle: line.speaker.filter(|_| named_senders).map(str::to_owned),
                    delivery_state: outbound.then_some(MobileStoredChatDeliveryState::Acknowledged),
                    reception: (!outbound).then(|| reception(index)),
                    reactions: line
                        .reactions
                        .iter()
                        .map(|reaction| {
                            let from = reaction.from.and_then(&resolve);
                            MobileStagedChatReactionRecord {
                                body: reaction.token.to_owned(),
                                outbound: reaction.from.is_none(),
                                created_at_ms: self.ago(reaction.minutes_ago),
                                sender_address: from.map(|from| from.address.clone()),
                                sender_hint: from.map(|from| from.hint.clone()),
                            }
                        })
                        .collect(),
                    regarding: line.reply_to.map(|reply| match reply {
                        Reply::Line(index) => {
                            MobileStagedChatRegarding::Message { handle: index + 1 }
                        }
                        Reply::Missing => MobileStagedChatRegarding::Missing,
                    }),
                    is_deleted: line.deleted,
                }
            })
            .collect()
    }
}

/// Plausible link metrics, varied per message: a transcript where every
/// frame arrived at the same RSSI would read as fabricated.
fn reception(index: usize) -> MobileStoredChatReceptionRecord {
    let index = index as i16;
    let relayed = index % 3 == 0;
    MobileStoredChatReceptionRecord {
        rssi_dbm: Some(-78 - (index * 7) % 24),
        snr_centibels: Some(620 - (index * 90) % 380),
        lqi: None,
        hop_count: Some(if relayed { 2 } else { 1 }),
        route_hints: if relayed {
            vec![vec![0x2A, 0xE1]]
        } else {
            Vec::new()
        },
        source_authenticated: true,
    }
}

struct StagedChannel {
    name: &'static str,
    kind: MobileStoredChannelKind,
    canonical_name: Option<String>,
    key: ChannelKey,
    max_flood_hops: Option<u8>,
    joined_days_ago: i64,
    session_id: &'static str,
    lines: &'static [Line],
}

/// One line of a staged conversation. `minutes_ago` counts back from the
/// seed's `now`, so a transcript always reads freshly.
struct Line {
    /// Who said it; none is the phone's owner.
    speaker: Option<&'static str>,
    body: &'static str,
    minutes_ago: i64,
    reactions: &'static [Reaction],
    reply_to: Option<Reply>,
    /// Taken back since.
    deleted: bool,
}

struct Reaction {
    token: &'static str,
    /// Who reacted; none is the phone's owner.
    from: Option<&'static str>,
    minutes_ago: i64,
}

#[derive(Clone, Copy)]
enum Reply {
    /// An earlier line of the same script, by index.
    Line(u32),
    /// A message this phone never received.
    Missing,
}

const fn said(speaker: &'static str, body: &'static str, minutes_ago: i64) -> Line {
    Line {
        speaker: Some(speaker),
        body,
        minutes_ago,
        reactions: &[],
        reply_to: None,
        deleted: false,
    }
}

const fn sent(body: &'static str, minutes_ago: i64) -> Line {
    Line {
        speaker: None,
        body,
        minutes_ago,
        reactions: &[],
        reply_to: None,
        deleted: false,
    }
}

impl Line {
    const fn reacted(self, reactions: &'static [Reaction]) -> Self {
        Self { reactions, ..self }
    }

    const fn replying(self, reply: Reply) -> Self {
        Self {
            reply_to: Some(reply),
            ..self
        }
    }

    const fn taken_back(self) -> Self {
        Self {
            deleted: true,
            ..self
        }
    }
}

const fn by(from: &'static str, token: &'static str, minutes_ago: i64) -> Reaction {
    Reaction {
        token,
        from: Some(from),
        minutes_ago,
    }
}

const fn mine(token: &'static str, minutes_ago: i64) -> Reaction {
    Reaction {
        token,
        from: None,
        minutes_ago,
    }
}

struct DirectScript {
    peer: &'static str,
    mark_read: bool,
    lines: &'static [Line],
}

const DIRECT_SCRIPTS: &[DirectScript] = &[
    DirectScript {
        peer: "Maya Ortiz",
        // Left unread, so the conversations list shows a badge.
        mark_read: false,
        lines: &[
            said("Maya Ortiz", "Heading up the north spur now. Should have eyes on the washout in about forty minutes.", 96),
            sent("Copy. Dev's already at the lower crossing with the saw.", 94),
            said("Maya Ortiz", "Perfect. Tell him the culvert at mile 3 is completely packed with gravel—we'll need the mattock.", 91)
                .reacted(&[mine("+1", 90)]),
            sent("Passing it along. Radio check in an hour?", 88).replying(Reply::Line(2)),
            said("Maya Ortiz", "Works. Signal's holding fine off the ridge repeater up here.", 86),
            said("Maya Ortiz", "At the washout. It's worse than the photos—about twelve feet of tread gone and the uphill bank is still moving.", 12),
            said("Maya Ortiz", "Going to flag it and back off. Not something we fix today.", 11),
            sent("Agreed, don't push it. Flag both approaches and we'll scope it properly Thursday.", 9)
                .reacted(&[by("Maya Ortiz", "+1", 8)]),
            said("Maya Ortiz", "On it. Heading back down to meet Dev.", 4)
                .reacted(&[mine("<3", 3)])
                .replying(Reply::Line(7)),
        ],
    },
    DirectScript {
        peer: "Dev Raman",
        mark_read: true,
        lines: &[
            sent("How's the lower crossing looking?", 140),
            said("Dev Raman", "Two deadfalls across, both about 18 inches. Working the second one now.", 137),
            sent("Nice. Maya says bring the mattock when you head up—culvert at mile 3 is packed solid.", 133),
            said("Dev Raman", "Got it in the pack already. Give me an hour here.", 131)
                .reacted(&[mine("+1", 130)]),
            sent("Can you check the sign at the upper junction on your way?", 60).taken_back(),
            said("Dev Raman", "Ha, saw you take that back. Checked it anyway, it's fine.", 52)
                .replying(Reply::Line(4)),
            said("Dev Raman", "Still want me on that after lunch?", 24).replying(Reply::Missing),
            said("Dev Raman", "Second one's clear. Tread's in better shape than last season through here.", 18),
            sent("Good news for once.", 16)
                .reacted(&[by("Dev Raman", "ha", 15)])
                .replying(Reply::Line(7)),
        ],
    },
    DirectScript {
        peer: "Jules Whitaker",
        mark_read: true,
        lines: &[
            said("Jules Whitaker", "Are we still meeting at the Echo lot at seven Thursday?", 320),
            sent("Seven sharp. Bringing the rock bar and both mattocks.", 316),
            said("Jules Whitaker", "I'll have the crosscut and enough water for four.", 310)
                .reacted(&[mine("+1", 308)]),
            sent("You're a hero. See you then.", 305),
        ],
    },
];

/// The crew channel: several voices, so sender names, per-sender colors,
/// and reactions from more than one person have something to render.
const CHANNEL_LINES: &[Line] = &[
    said("Echo Basecamp", "Morning all. Weather's holding through about four, then a chance of thunder over the crest.", 210)
        .reacted(&[by("Maya Ortiz", "+1", 208), by("Dev Raman", "+1", 206)]),
    said("Maya Ortiz", "Taking the north spur. Dev's on the lower crossing.", 205),
    said("Dev Raman", "Two deadfalls down here, nothing we can't handle.", 201),
    sent("I'll stage the tools at the Echo lot for Thursday. Anyone need anything specific?", 198),
    said("Jules Whitaker", "Another rock bar if we have one. The one we've got is bent.", 194)
        .reacted(&[by("Dev Raman", "ha", 192)])
        .replying(Reply::Line(3)),
    said("Echo Basecamp", "Reminder that the upper loop is still closed to stock until the bridge inspection clears.", 150),
    said("Maya Ortiz", "Washout at the north spur is bigger than reported. Twelve feet of tread gone, bank still active. Flagging both approaches.", 12)
        .reacted(&[by("Echo Basecamp", "!", 11), by("Jules Whitaker", "!", 10), mine("!", 9)]),
    said("Echo Basecamp", "Noted. I'll get it on the closure list tonight and pull the district engineer in.", 8)
        .replying(Reply::Line(6)),
    sent("Thanks. Nobody goes past the flags until we've scoped it properly.", 6)
        .reacted(&[by("Maya Ortiz", "+1", 5), by("Jules Whitaker", "+1", 4)]),
];

/// The private channel: fewer people, and why it is private shows in what
/// is said on it.
const PRIVATE_CHANNEL_LINES: &[Line] = &[
    said(
        "Echo Basecamp",
        "Leads only—budget came back and it's about 30% short of what we asked for.",
        1_450,
    ),
    sent(
        "That's the bridge decking gone then. Can we phase it?",
        1_446,
    ),
    said(
        "Echo Basecamp",
        "Phasing is what I'd propose. Decking next season, abutment repair this one.",
        1_441,
    )
    .reacted(&[by("Maya Ortiz", "+1", 1_439)]),
    said(
        "Maya Ortiz",
        "Works for me. The abutment is the safety item anyway—the decking is just uncomfortable.",
        1_436,
    ),
    sent(
        "Let's not put the numbers on the open channel until the district signs off.",
        1_430,
    )
    .reacted(&[
        by("Echo Basecamp", "+1", 1_428),
        by("Maya Ortiz", "+1", 1_427),
    ]),
    said(
        "Echo Basecamp",
        "Agreed. I'll have a written version for you both by Thursday.",
        1_425,
    ),
    said(
        "Maya Ortiz",
        "Given what I saw at the north spur today we should get the washout into the same request.",
        7,
    ),
    sent("Good call. Send me photos and I'll fold it in.", 5).reacted(&[by("Maya Ortiz", "+1", 4)]),
];

#[cfg(test)]
mod tests;
