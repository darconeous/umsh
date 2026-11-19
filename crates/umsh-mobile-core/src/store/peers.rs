//! The local identity rows and the peers (`node` rows) each identity knows.

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OptionalExtension, params};
use unicode_normalization::{UnicodeNormalization, char::canonical_combining_class};

use super::{MobileAppStore, MobileStoreError};

/// What the app itself made of a node, as against what the node says it
/// is. Stored as lowercase TEXT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileStoredSystemRole {
    /// The radio this phone is attached to. An identity has one.
    CompanionRadio,
}

impl MobileStoredSystemRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::CompanionRadio => COMPANION_RADIO,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        (value == COMPANION_RADIO).then_some(Self::CompanionRadio)
    }
}

/// The `system_role` text of the companion radio's row, as SQL names it.
pub(super) const COMPANION_RADIO: &str = "companion_radio";

/// The role a node last advertised, as the app names it. Stored as the
/// TEXT the Swift store wrote: the role's name in lower camel case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileStoredNodeKind {
    Repeater,
    Chat,
    Tracker,
    Sensor,
    Bridge,
    ChatRoom,
    TemporarySession,
    /// The node claimed a role byte the app has no name for.
    Unknown,
}

impl MobileStoredNodeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Repeater => "repeater",
            Self::Chat => "chat",
            Self::Tracker => "tracker",
            Self::Sensor => "sensor",
            Self::Bridge => "bridge",
            Self::ChatRoom => "chatRoom",
            Self::TemporarySession => "temporarySession",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "repeater" => Self::Repeater,
            "chat" => Self::Chat,
            "tracker" => Self::Tracker,
            "sensor" => Self::Sensor,
            "bridge" => Self::Bridge,
            "chatRoom" => Self::ChatRoom,
            "temporarySession" => Self::TemporarySession,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

/// One peer as the store holds it.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredNodeRecord {
    pub id: i64,
    pub owner_identity_id: String,
    pub public_address: String,
    pub alias: Option<String>,
    pub advertised_name: Option<String>,
    /// `None` for an ordinary peer, and for a role this build does not
    /// know.
    pub system_role: Option<MobileStoredSystemRole>,
    /// `None` until a role is heard, and for a kind this build does not
    /// know.
    pub node_kind: Option<MobileStoredNodeKind>,
    /// Raw advertised-identity payload bytes (node-identity.md wire form).
    pub advertisement: Option<Vec<u8>>,
    /// Whether the MAC authenticated the frame that delivered
    /// `advertisement`. A bundle that arrived as a MIC-authenticated unicast
    /// reply carries no signature of its own, so this is the only surviving
    /// evidence that it really came from the peer.
    pub advertisement_authenticated: bool,
    /// When we last heard from this peer by any means (advertisement,
    /// inbound message, delivery ack, ping reply). `None` until the first
    /// inbound evidence lands.
    pub last_heard_at_ms: Option<i64>,
    /// Whether this node is saved on the local (phone) identity. Rows with
    /// `false` are the transient tier: heard on the air, kept for search and
    /// discovery, hidden from the main Peers list, and subject to retention.
    pub is_saved: bool,
    pub is_favorite: bool,
    /// Cache of whether this node's public key is stored on the companion
    /// radio's device identity (`PROP_DEV_PEERS`). The device is the
    /// authority; this flag is reconciled from it on attach.
    pub on_device_identity: bool,
    /// Whether a one-shot watch is armed on this node: tell the user the
    /// next time anything is heard from it, then disarm. Cleared by the same
    /// write that records the hearing, so the notice fires exactly once.
    pub notify_when_heard: bool,
    /// When `advertisement` was heard off the air. `None` for a bundle that
    /// was imported: nothing about how it arrived dates what it says.
    pub advertisement_received_at_ms: Option<i64>,
}

/// What an upsert says about a peer; see [`MobileAppStore::upsert_peer`]
/// for how it merges with the stored row.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobilePeerUpsertRecord {
    pub alias: Option<String>,
    #[uniffi(default)]
    pub advertised_name: Option<String>,
    #[uniffi(default)]
    pub is_saved: bool,
    #[uniffi(default)]
    pub node_kind: Option<MobileStoredNodeKind>,
    #[uniffi(default)]
    pub system_role: Option<MobileStoredSystemRole>,
    #[uniffi(default)]
    pub radio_identifier: Option<String>,
    #[uniffi(default)]
    pub advertisement: Option<Vec<u8>>,
    #[uniffi(default)]
    pub advertisement_authenticated: bool,
    #[uniffi(default)]
    pub advertisement_received_at_ms: Option<i64>,
}

#[uniffi::export]
impl MobileAppStore {
    pub fn insert_identity(
        &self,
        id: String,
        public_address: String,
        created_at_ms: i64,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "INSERT INTO local_identity (id, public_address, created_at_ms) VALUES (?, ?, ?)",
            params![id, public_address, created_at_ms],
        )?;
        Ok(())
    }

    pub fn upsert_identity(
        &self,
        id: String,
        public_address: String,
        created_at_ms: i64,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "INSERT INTO local_identity (id, public_address, created_at_ms) VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET public_address = excluded.public_address",
            params![id, public_address, created_at_ms],
        )?;
        Ok(())
    }

    /// Whether this store already holds records for the given identity.
    ///
    /// Asked when a stored identity turns up with no anchor beside it: a
    /// container that still has this identity's row is that identity's
    /// container, anchor or no anchor, and there is nothing to ask about.
    /// The legacy `'primary'` slot counts, since a store written before the
    /// address became the key is still this identity's store.
    pub fn knows_identity(
        &self,
        id: String,
        public_address: String,
    ) -> Result<bool, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT 1 FROM local_identity
                WHERE id = ? OR (id = 'primary' AND public_address = ?)
                LIMIT 1",
                params![id, public_address],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Record a peer, or add what this call knows to the row already there.
    ///
    /// An absent alias, name, role, radio identifier, kind, or advertisement
    /// leaves the stored one in place, and `is_saved` only ever rises here.
    /// The advertisement's provenance (`advertisement_authenticated`,
    /// `advertisement_received_at_ms`) is written only with an
    /// advertisement. The sort key follows the row as it ends up: its
    /// alias or, without one, its advertised name.
    pub fn upsert_peer(
        &self,
        owner_identity_id: String,
        public_address: String,
        peer: MobilePeerUpsertRecord,
    ) -> Result<(), MobileStoreError> {
        upsert_peer(
            &self.connection(),
            &owner_identity_id,
            &public_address,
            &peer,
        )
    }

    pub fn local_advertised_name(
        &self,
        owner_identity_id: String,
    ) -> Result<Option<String>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT advertised_name FROM local_identity WHERE id = ?",
                params![owner_identity_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten())
    }

    /// Fails with [`MobileStoreError::RecordNotFound`] when there is no
    /// such identity.
    pub fn update_local_advertised_name(
        &self,
        owner_identity_id: String,
        name: Option<String>,
    ) -> Result<(), MobileStoreError> {
        let changes = self.connection().execute(
            "UPDATE local_identity SET advertised_name = ? WHERE id = ?",
            params![name, owner_identity_id],
        )?;
        if changes != 1 {
            return Err(MobileStoreError::RecordNotFound);
        }
        Ok(())
    }

    pub fn update_node_alias(
        &self,
        owner_identity_id: String,
        public_address: String,
        alias: Option<String>,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            // The sort key falls back to the advertised name when the
            // alias is cleared, matching upsert_peer's initial insert.
            let Some(advertised_name) = transaction
                .query_row(
                    "SELECT advertised_name FROM node
                    WHERE owner_identity_id = ? AND public_address = ?",
                    params![owner_identity_id, public_address],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
            else {
                return Ok(());
            };
            let search = search_key(alias.as_deref(), advertised_name.as_deref());
            transaction.execute(
                "UPDATE node SET alias = ?, alias_search = ?
                WHERE owner_identity_id = ? AND public_address = ?",
                params![alias, search, owner_identity_id, public_address],
            )?;
            Ok(())
        })
    }

    pub fn set_peer_favorite(
        &self,
        owner_identity_id: String,
        public_address: String,
        is_favorite: bool,
    ) -> Result<(), MobileStoreError> {
        // Favoriting implies saving: the star lives in the main list, so a
        // favorite hidden in the transient tier would be unreachable.
        self.connection().execute(
            "UPDATE node SET is_favorite = ?1,
                is_saved = CASE WHEN ?1 = 1 THEN 1 ELSE is_saved END
            WHERE owner_identity_id = ?2 AND public_address = ?3",
            params![is_favorite, owner_identity_id, public_address],
        )?;
        Ok(())
    }

    /// Record a transient node on the local identity, making it visible in
    /// the main Peers list.
    pub fn promote_peer_to_saved(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "UPDATE node SET is_saved = 1
            WHERE owner_identity_id = ? AND public_address = ?",
            params![owner_identity_id, public_address],
        )?;
        Ok(())
    }

    /// Remove a node from the local identity without touching its history:
    /// the row stays as a transient (searchable, discoverable) and any
    /// conversation keeps working. Favorite and alias are local statements
    /// about a saved peer, so they clear with it. Refuses the companion
    /// radio, whose row is system-managed.
    pub fn demote_peer_to_transient(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            let Some(advertised_name) = transaction
                .query_row(
                    "SELECT advertised_name FROM node
                    WHERE owner_identity_id = ? AND public_address = ?
                        AND (system_role IS NULL OR system_role <> ?)",
                    params![owner_identity_id, public_address, COMPANION_RADIO],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
            else {
                return Ok(());
            };
            transaction.execute(
                "UPDATE node SET is_saved = 0, is_favorite = 0,
                    alias = NULL, alias_search = ?
                WHERE owner_identity_id = ? AND public_address = ?",
                params![
                    search_key(None, advertised_name.as_deref()),
                    owner_identity_id,
                    public_address
                ],
            )?;
            Ok(())
        })
    }

    /// Delete a peer row outright. Refused—returning `false`—when a
    /// conversation references it (demote instead, or use
    /// `delete_peer_and_conversation`) or when the row is the system-managed companion
    /// radio. Stream checkpoints and counter state survive by design:
    /// sequence continuity and replay protection outlive the row.
    pub fn delete_peer(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<bool, MobileStoreError> {
        let changes = self.connection().execute(
            "DELETE FROM node
            WHERE owner_identity_id = ?1 AND public_address = ?2
                AND (system_role IS NULL OR system_role <> ?3)
                AND id NOT IN (
                    SELECT node_id FROM direct_conversation WHERE owner_identity_id = ?1
                )",
            params![owner_identity_id, public_address, COMPANION_RADIO],
        )?;
        Ok(changes > 0)
    }

    /// Drop every transient row that nothing else depends on: saved peers,
    /// the companion radio, rows on the device identity, rows with a
    /// conversation, and rows carrying a pending watch all stay.
    pub fn clear_transient_peers(&self, owner_identity_id: String) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "DELETE FROM node
            WHERE owner_identity_id = ?1 AND is_saved = 0 AND on_dev_identity = 0
                AND system_role IS NULL AND notify_when_heard = 0
                AND id NOT IN (
                    SELECT node_id FROM direct_conversation WHERE owner_identity_id = ?1
                )",
            params![owner_identity_id],
        )?;
        Ok(())
    }

    /// Keep the transient tier bounded: beyond `cap` rows, the oldest-heard
    /// evictable transients are dropped. Rows with a conversation, on the
    /// device identity, with a system role, or carrying a pending watch are
    /// never evicted—a watch that the cap quietly deleted would be a
    /// promise the app stopped keeping without saying so. `cap` defaults to
    /// 256.
    #[uniffi::method(default(cap = 256))]
    pub fn enforce_transient_retention(
        &self,
        owner_identity_id: String,
        cap: u32,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "DELETE FROM node WHERE id IN (
                SELECT id FROM node
                WHERE owner_identity_id = ?1 AND is_saved = 0 AND on_dev_identity = 0
                    AND system_role IS NULL AND notify_when_heard = 0
                    AND id NOT IN (
                        SELECT node_id FROM direct_conversation WHERE owner_identity_id = ?1
                    )
                ORDER BY last_heard_at DESC, id DESC
                LIMIT -1 OFFSET ?2
            )",
            params![owner_identity_id, cap],
        )?;
        Ok(())
    }

    /// Make the local cache of the radio's device-identity peer list match
    /// the device's read-back. The device is the authority: flags clear
    /// where it no longer holds a key, set where it does, and unknown keys
    /// gain a transient row carrying the flag so lists can show them.
    pub fn reconcile_device_identity_peers(
        &self,
        owner_identity_id: String,
        addresses: Vec<String>,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            transaction.execute(
                "UPDATE node SET on_dev_identity = 0
                WHERE owner_identity_id = ? AND on_dev_identity = 1",
                params![owner_identity_id],
            )?;
            for address in &addresses {
                mark_on_device_identity(transaction, &owner_identity_id, address)?;
            }
            Ok(())
        })
    }

    /// Cache one device-identity membership change after a confirmed radio
    /// mutation, without waiting for the next attach-edge reconcile.
    pub fn set_peer_on_device_identity(
        &self,
        owner_identity_id: String,
        public_address: String,
        is_on_device_identity: bool,
    ) -> Result<(), MobileStoreError> {
        let connection = self.connection();
        if is_on_device_identity {
            mark_on_device_identity(&connection, &owner_identity_id, &public_address)?;
        } else {
            connection.execute(
                "UPDATE node SET on_dev_identity = 0
                WHERE owner_identity_id = ? AND public_address = ?",
                params![owner_identity_id, public_address],
            )?;
        }
        Ok(())
    }

    /// Arm or disarm the one-shot "tell me the next time this node is heard"
    /// watch. Unlike favoriting, this does not save a transient node: the
    /// retention queries exempt armed rows instead, so asking to be told
    /// about a node is not the same as deciding to keep it.
    pub fn set_notify_when_heard(
        &self,
        owner_identity_id: String,
        public_address: String,
        enabled: bool,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "UPDATE node SET notify_when_heard = ?
            WHERE owner_identity_id = ? AND public_address = ?",
            params![enabled, owner_identity_id, public_address],
        )?;
        Ok(())
    }

    /// Record that we just heard from a peer by any means. No-ops when the
    /// peer has no row—an unknown peer has nothing to touch and needs no
    /// last-heard until it is added.
    ///
    /// Returns whether this call is the one that disarmed a pending watch,
    /// which is the caller's cue to post the notice. The disarm is its own
    /// conditional write, so two hearings racing through the store cannot
    /// both come away believing they were first.
    pub fn touch_last_heard(
        &self,
        owner_identity_id: String,
        public_address: String,
        at_ms: i64,
    ) -> Result<bool, MobileStoreError> {
        self.write(|transaction| {
            let fired_watch = transaction.execute(
                "UPDATE node SET notify_when_heard = 0
                WHERE owner_identity_id = ? AND public_address = ? AND notify_when_heard = 1",
                params![owner_identity_id, public_address],
            )? > 0;
            transaction.execute(
                "UPDATE node SET last_heard_at = ?
                WHERE owner_identity_id = ? AND public_address = ?",
                params![seconds(at_ms), owner_identity_id, public_address],
            )?;
            Ok(fired_watch)
        })
    }

    /// Record the attached companion radio as the identity's one
    /// `companion_radio` row, taking the role from any other row that held
    /// it.
    pub fn upsert_ulcp_device_peer(
        &self,
        owner_identity_id: String,
        public_address: String,
        advertised_name: Option<String>,
        radio_identifier: String,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            transaction.execute(
                "UPDATE node SET system_role = NULL, radio_identifier = NULL
                WHERE owner_identity_id = ? AND system_role = ?
                    AND public_address <> ?",
                params![owner_identity_id, COMPANION_RADIO, public_address],
            )?;
            upsert_peer(
                transaction,
                &owner_identity_id,
                &public_address,
                &MobilePeerUpsertRecord {
                    alias: None,
                    advertised_name,
                    is_saved: true,
                    system_role: Some(MobileStoredSystemRole::CompanionRadio),
                    radio_identifier: Some(radio_identifier),
                    ..MobilePeerUpsertRecord::default()
                },
            )?;
            Ok(())
        })
    }

    /// Every peer of the identity: system rows first, then by the sort
    /// key. Name order is the platform's to impose.
    pub fn list_nodes(
        &self,
        owner_identity_id: String,
    ) -> Result<Vec<MobileStoredNodeRecord>, MobileStoreError> {
        list_nodes(&self.connection(), &owner_identity_id)
    }
}

pub(super) fn list_nodes(
    connection: &Connection,
    owner_identity_id: &str,
) -> Result<Vec<MobileStoredNodeRecord>, MobileStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT {} FROM node WHERE owner_identity_id = ?
        ORDER BY (system_role IS NOT NULL) DESC, alias_search, id",
        node_columns("")
    ))?;
    let nodes = statement
        .query_map(params![owner_identity_id], |row| stored_node(row, 0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(nodes)
}

/// This identity's row for a peer, or `None` for one it does not store. A
/// peer with no row has nowhere to hang a cache or a route, which is
/// ordinary rather than an error: nothing is kept about a stranger.
pub(super) fn node_id(
    connection: &Connection,
    owner_identity_id: &str,
    public_address: &str,
) -> Result<Option<i64>, MobileStoreError> {
    Ok(connection
        .query_row(
            "SELECT id FROM node WHERE owner_identity_id = ? AND public_address = ?",
            params![owner_identity_id, public_address],
            |row| row.get(0),
        )
        .optional()?)
}

/// The node columns, in the order [`stored_node`] reads them.
const NODE_COLUMNS: [&str; 15] = [
    "id",
    "owner_identity_id",
    "public_address",
    "alias",
    "advertised_name",
    "system_role",
    "node_kind",
    "advertisement",
    "advertisement_authenticated",
    "last_heard_at",
    "is_saved",
    "is_favorite",
    "on_dev_identity",
    "notify_when_heard",
    "advertisement_received_at",
];

/// How many columns [`stored_node`] reads.
pub(super) const NODE_COLUMN_COUNT: usize = NODE_COLUMNS.len();

/// [`NODE_COLUMNS`] as a select list, each qualified by `prefix` (`"n."`
/// in a join).
pub(super) fn node_columns(prefix: &str) -> String {
    NODE_COLUMNS
        .iter()
        .map(|column| format!("{prefix}{column}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The node a row holds in [`NODE_COLUMNS`] order, starting at `offset`.
pub(super) fn stored_node(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<MobileStoredNodeRecord> {
    Ok(MobileStoredNodeRecord {
        id: row.get(offset)?,
        owner_identity_id: row.get(offset + 1)?,
        public_address: row.get(offset + 2)?,
        alias: row.get(offset + 3)?,
        advertised_name: row.get(offset + 4)?,
        system_role: row
            .get::<_, Option<String>>(offset + 5)?
            .as_deref()
            .and_then(MobileStoredSystemRole::parse),
        node_kind: row
            .get::<_, Option<String>>(offset + 6)?
            .as_deref()
            .and_then(MobileStoredNodeKind::parse),
        advertisement: row.get(offset + 7)?,
        advertisement_authenticated: row.get::<_, i64>(offset + 8)? != 0,
        last_heard_at_ms: row.get::<_, Option<f64>>(offset + 9)?.map(milliseconds),
        is_saved: row.get::<_, i64>(offset + 10)? != 0,
        is_favorite: row.get::<_, i64>(offset + 11)? != 0,
        on_device_identity: row.get::<_, i64>(offset + 12)? != 0,
        notify_when_heard: row.get::<_, i64>(offset + 13)? != 0,
        advertisement_received_at_ms: row.get::<_, Option<f64>>(offset + 14)?.map(milliseconds),
    })
}

fn upsert_peer(
    connection: &Connection,
    owner_identity_id: &str,
    public_address: &str,
    peer: &MobilePeerUpsertRecord,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "INSERT INTO node (
            owner_identity_id, public_address, alias, alias_search,
            advertised_name, is_saved, system_role, radio_identifier,
            node_kind, advertisement, advertisement_authenticated,
            advertisement_received_at
        ) VALUES (?1, ?2, ?3, umsh_search_key(?3, ?4), ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(owner_identity_id, public_address) DO UPDATE SET
            alias = COALESCE(excluded.alias, node.alias),
            -- From the values this update leaves, so a name heard later
            -- moves an alias-less peer in the sort. (The Swift store kept
            -- the old key whenever the update carried no alias.)
            alias_search = umsh_search_key(
                COALESCE(excluded.alias, node.alias),
                COALESCE(excluded.advertised_name, node.advertised_name)),
            advertised_name = COALESCE(excluded.advertised_name, node.advertised_name),
            -- A background advertisement upsert must never demote a saved
            -- peer to the transient tier; only the explicit demote/delete
            -- setters move a row downward.
            is_saved = MAX(node.is_saved, excluded.is_saved),
            system_role = COALESCE(excluded.system_role, node.system_role),
            radio_identifier = COALESCE(excluded.radio_identifier, node.radio_identifier),
            node_kind = COALESCE(excluded.node_kind, node.node_kind),
            advertisement = COALESCE(excluded.advertisement, node.advertisement),
            -- Provenance belongs to the bundle it describes, so it moves
            -- only when the bundle does. A call that carries no
            -- advertisement leaves all three untouched.
            advertisement_authenticated = CASE WHEN excluded.advertisement IS NULL
                THEN node.advertisement_authenticated
                ELSE excluded.advertisement_authenticated END,
            advertisement_received_at = CASE WHEN excluded.advertisement IS NULL
                THEN node.advertisement_received_at
                ELSE excluded.advertisement_received_at END",
        params![
            owner_identity_id,
            public_address,
            peer.alias,
            peer.advertised_name,
            peer.is_saved,
            peer.system_role.map(MobileStoredSystemRole::as_str),
            peer.radio_identifier,
            peer.node_kind.map(MobileStoredNodeKind::as_str),
            peer.advertisement,
            peer.advertisement_authenticated,
            peer.advertisement_received_at_ms.map(seconds),
        ],
    )?;
    Ok(())
}

/// Set the device-identity flag, creating a transient row when the key is
/// not otherwise recorded on this phone.
fn mark_on_device_identity(
    connection: &Connection,
    owner_identity_id: &str,
    public_address: &str,
) -> Result<(), MobileStoreError> {
    connection.execute(
        "INSERT INTO node (owner_identity_id, public_address, alias_search, on_dev_identity)
        VALUES (?, ?, '', 1)
        ON CONFLICT(owner_identity_id, public_address) DO UPDATE SET on_dev_identity = 1",
        params![owner_identity_id, public_address],
    )?;
    Ok(())
}

/// The key a node row keeps in `alias_search`, which [`list_nodes`] orders
/// by: its alias or, without one, its advertised name, folded. Every write
/// that changes either column derives the key here, in Rust or through
/// `umsh_search_key` in SQL.
///
/// Nothing searches by the column, whatever its name says. It is a base
/// order only: the platforms sort names by the reader's locale themselves.
pub(super) fn search_key(alias: Option<&str>, advertised_name: Option<&str>) -> String {
    fold_search(alias.or(advertised_name).unwrap_or(""))
}

/// The form `alias_search` holds: canonical decomposition with every mark
/// of a nonzero combining class (accents, cedillas, tone marks) removed,
/// lowercased with a single sigma, then recomposed. Close to the fold the
/// Swift store wrote with Foundation, so rows either store wrote sort
/// together.
///
/// Marks of combining class zero, such as most vowel signs of Indic
/// scripts, stay. Recomposing keeps text without marks in its usual form
/// (a Hangul syllable stays one character rather than its jamo).
pub(super) fn fold_search(value: &str) -> String {
    let unmarked: String = value
        .nfd()
        .filter(|c| canonical_combining_class(*c) == 0)
        .collect();
    // Lowercasing writes a word-final Σ as ς; one sigma keeps a prefix
    // typed mid-word matching the whole word's key.
    unmarked
        .to_lowercase()
        .nfc()
        .map(|c| if c == 'ς' { 'σ' } else { c })
        .collect()
}

/// Make [`search_key`] callable from SQL on `connection`, as
/// `umsh_search_key(alias, advertised_name)`.
pub(super) fn register_functions(connection: &Connection) -> rusqlite::Result<()> {
    connection.create_scalar_function(
        "umsh_search_key",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let alias = context.get::<Option<String>>(0)?;
            let advertised_name = context.get::<Option<String>>(1)?;
            Ok(search_key(alias.as_deref(), advertised_name.as_deref()))
        },
    )
}

/// A REAL Unix-seconds column's value for an instant in milliseconds.
fn seconds(milliseconds: i64) -> f64 {
    milliseconds as f64 / 1_000.0
}

/// An instant in milliseconds from a REAL Unix-seconds column. Rounded, so
/// a value written by [`seconds`] reads back exactly.
fn milliseconds(seconds: f64) -> i64 {
    (seconds * 1_000.0).round() as i64
}

#[cfg(test)]
mod tests;
