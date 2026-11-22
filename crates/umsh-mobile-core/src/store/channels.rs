//! The channels each identity knows: public metadata only. A channel's
//! 32-byte key lives in the platform's secret vault, under the channel's ID.
//!
//! That ID is a UUID, stored in Foundation's `uuidString` form: uppercase
//! and hyphenated. Because it is also the vault's account name, every ID
//! that crosses this boundary is put in that form first, so a lowercase ID
//! (what `java.util.UUID` prints) names the same channel and the same vault
//! entry on both platforms. Stored IDs are read back in that form too.

use rusqlite::{Connection, OptionalExtension, params};

use super::conversations::purge_conversation_history;
use super::{MobileAppStore, MobileStoreError, clamp};

/// How a channel's key was established, which decides what may be shared.
/// Stored as lowercase TEXT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileStoredChannelKind {
    /// `public` or `EMERGENCY`: named channels the protocol fixes rules for.
    /// These rows are never deleted—leaving clears the joined flags so the
    /// channel can be offered again.
    Builtin,
    /// Key derived from a name anyone may know, so the name is shareable.
    Named,
    /// Key distributed out of band; the invitation is a secret.
    PrivateKey,
}

impl MobileStoredChannelKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Named => "named",
            Self::PrivateKey => "private",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "builtin" => Some(Self::Builtin),
            "named" => Some(Self::Named),
            "private" => Some(Self::PrivateKey),
            _ => None,
        }
    }
}

/// A channel this identity knows about.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredChannelRecord {
    /// Uppercase hyphenated UUID; the secret vault's account name for the
    /// channel's key. Any case is accepted on the way in.
    pub id: String,
    pub owner_identity_id: String,
    pub kind: MobileStoredChannelKind,
    /// Canonical lowercase name the key is derived from. Key-derivation
    /// machinery, not something to show: `name` is what the channel is
    /// called.
    pub canonical_name: Option<String>,
    /// The channel's own name, written the way it was typed or shared.
    pub name: Option<String>,
    /// What this user calls the channel. Takes display precedence but never
    /// overwrites `name`, matching how a peer alias works.
    pub alias: Option<String>,
    /// Two-octet derived identifier, hex. A hint, not an identity: distinct
    /// keys may collide here.
    pub channel_id_hex: String,
    /// Three presentation octets—the identifier extended by one byte—kept
    /// here so a list can color its rows without unlocking every key.
    pub tint: Vec<u8>,
    /// The channel's one region code, as its octets.
    pub region_code: Option<Vec<u8>>,
    /// How far the channel's messages flood, when it sets a limit.
    pub max_flood_hops: Option<u8>,
    /// Whether the phone identity has joined. Drives MAC registration and
    /// the radio's host channel table.
    pub joined_phone: bool,
    /// Whether the companion radio's device identity has joined. Nothing
    /// keeps it current: the radio's own channels are managed apart from
    /// the phone's, and nothing the phone does reads it.
    pub joined_device: bool,
    pub notifications_enabled: bool,
    /// When the phone identity first joined. Stamped once and kept through
    /// later leaves and rejoins.
    pub joined_at_ms: Option<i64>,
}

#[uniffi::export]
impl MobileAppStore {
    /// Every channel of the identity, oldest first. A row whose ID is not a
    /// UUID or whose kind this build does not know is left out, not an
    /// error: one bad row must not hide the rest.
    pub fn channels(
        &self,
        owner_identity_id: String,
    ) -> Result<Vec<MobileStoredChannelRecord>, MobileStoreError> {
        channels(&self.connection(), &owner_identity_id)
    }

    /// The channel this identity already holds under `key_digest`, if any.
    ///
    /// Import checks this before inserting so a re-scanned invitation
    /// updates the existing channel instead of creating a second one for the
    /// same key.
    pub fn channel(
        &self,
        owner_identity_id: String,
        key_digest: String,
    ) -> Result<Option<MobileStoredChannelRecord>, MobileStoreError> {
        let connection = self.connection();
        let row = connection
            .query_row(
                &format!(
                    "SELECT {CHANNEL_COLUMNS} FROM channel
                    WHERE owner_identity_id = ? AND key_digest = ?"
                ),
                params![owner_identity_id, key_digest],
                stored_channel,
            )
            .optional()?;
        Ok(row.flatten())
    }

    /// Record a channel. `created_at_ms` orders it among the identity's
    /// channels; the record's `id` is stored uppercase. Fails with
    /// [`MobileStoreError::Failed`] when the identity already holds the ID
    /// or the key digest.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn insert_channel(
        &self,
        channel: MobileStoredChannelRecord,
        key_digest: String,
        created_at_ms: i64,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(&channel.id)?;
        self.connection().execute(
            "INSERT INTO channel (
                id, owner_identity_id, kind, canonical_name, name, alias,
                channel_id_hex, tint, key_digest, region_code, max_flood_hops,
                joined_phone, joined_device, notifications_enabled,
                created_at_ms, joined_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id,
                channel.owner_identity_id,
                channel.kind.as_str(),
                channel.canonical_name,
                channel.name,
                channel.alias,
                channel.channel_id_hex,
                channel.tint,
                key_digest,
                channel.region_code,
                channel.max_flood_hops,
                channel.joined_phone,
                channel.joined_device,
                channel.notifications_enabled,
                created_at_ms,
                channel.joined_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Update the parts of a channel the user controls, leaving membership
    /// and key-derived columns alone. A channel that does not exist is not
    /// an error.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn update_channel_details(
        &self,
        id: String,
        alias: Option<String>,
        region_code: Option<Vec<u8>>,
        max_flood_hops: Option<u8>,
        notifications_enabled: bool,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(&id)?;
        self.connection().execute(
            "UPDATE channel
            SET alias = ?, region_code = ?, max_flood_hops = ?,
                notifications_enabled = ?
            WHERE id = ?",
            params![
                alias,
                region_code,
                max_flood_hops,
                notifications_enabled,
                id
            ],
        )?;
        Ok(())
    }

    /// Record which identities have joined. `joined_at_ms` takes `now_ms`
    /// the first time the phone joins and is left alone after, through any
    /// number of leaves and rejoins. A channel that does not exist is not
    /// an error.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn set_channel_membership(
        &self,
        id: String,
        joined_phone: bool,
        joined_device: bool,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(&id)?;
        self.connection().execute(
            "UPDATE channel
            SET joined_phone = ?1, joined_device = ?2,
                joined_at_ms = CASE
                    WHEN ?1 = 1 AND joined_at_ms IS NULL THEN ?3 ELSE joined_at_ms
                END
            WHERE id = ?4",
            params![joined_phone, joined_device, now_ms, id],
        )?;
        Ok(())
    }

    /// Delete a channel row. Its conversation row goes with it (the schema
    /// cascades), but its transcript does not: a caller leaving a channel
    /// deletes the conversation first, through
    /// `delete_channel_conversation`, which purges the history. Nothing
    /// here refuses a built-in channel; leaving one clears its flags
    /// instead, and that is the caller's to choose.
    ///
    /// For tests and tools that seed a store with no core running; the app
    /// edits through `MobileAppCore`'s commands.
    pub fn delete_channel(&self, id: String) -> Result<(), MobileStoreError> {
        let id = channel_id(&id)?;
        self.connection()
            .execute("DELETE FROM channel WHERE id = ?", params![id])?;
        Ok(())
    }
}

/// The channel columns, in the order [`stored_channel`] reads them.
const CHANNEL_COLUMNS: &str = "id, owner_identity_id, kind, canonical_name, name, alias,
    channel_id_hex, tint, region_code, max_flood_hops, joined_phone, joined_device,
    notifications_enabled, joined_at_ms";

pub(super) fn channels(
    connection: &Connection,
    owner_identity_id: &str,
) -> Result<Vec<MobileStoredChannelRecord>, MobileStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT {CHANNEL_COLUMNS} FROM channel WHERE owner_identity_id = ?
        ORDER BY created_at_ms, id"
    ))?;
    let channels = statement
        .query_map(params![owner_identity_id], stored_channel)?
        .filter_map(Result::transpose)
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(channels)
}

/// The channel a row holds, or `None` for a row this build cannot read: an
/// ID that is not a UUID or a kind it does not know.
fn stored_channel(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<MobileStoredChannelRecord>> {
    let Some(id) = canonical_uuid(&row.get::<_, String>(0)?) else {
        return Ok(None);
    };
    let Some(kind) = MobileStoredChannelKind::parse(&row.get::<_, String>(2)?) else {
        return Ok(None);
    };
    Ok(Some(MobileStoredChannelRecord {
        id,
        owner_identity_id: row.get(1)?,
        kind,
        canonical_name: row.get(3)?,
        name: row.get(4)?,
        alias: row.get(5)?,
        channel_id_hex: row.get(6)?,
        tint: row.get(7)?,
        region_code: row.get(8)?,
        max_flood_hops: row.get::<_, Option<i64>>(9)?.map(clamp),
        joined_phone: row.get::<_, i64>(10)? != 0,
        joined_device: row.get::<_, i64>(11)? != 0,
        notifications_enabled: row.get::<_, i64>(12)? != 0,
        joined_at_ms: row.get(13)?,
    }))
}

/// A channel ID from across the boundary, in the stored form, or
/// [`MobileStoreError::InvalidArgument`] when it is not a UUID.
pub(super) fn channel_id(value: &str) -> Result<String, MobileStoreError> {
    canonical_uuid(value).ok_or(MobileStoreError::InvalidArgument)
}

/// `value` as Foundation's `UUID(uuidString:)` reads it and `uuidString`
/// writes it: 8-4-4-4-12 hex digits in either case, returned uppercase.
/// `None` for anything else.
pub(super) fn canonical_uuid(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let well_formed = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    well_formed.then(|| value.to_ascii_uppercase())
}

#[cfg(test)]
mod tests;

/// What `leave_channel` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeftChannel {
    /// The row went; a built-in channel's stays, left.
    pub(crate) deleted: bool,
    /// The address of the conversation purged with it, when it had one.
    pub(crate) conversation_address: Option<String>,
}

/// The app core's channel reads and writes.
impl MobileAppStore {
    /// The identity's channel with `id`, in any case, or `None`.
    pub(crate) fn channel_by_id(
        &self,
        owner_identity_id: &str,
        id: &str,
    ) -> Result<Option<MobileStoredChannelRecord>, MobileStoreError> {
        let id = channel_id(id)?;
        let row = self
            .connection()
            .query_row(
                &format!(
                    "SELECT {CHANNEL_COLUMNS} FROM channel
                    WHERE owner_identity_id = ? AND id = ?"
                ),
                params![owner_identity_id, id],
                stored_channel,
            )
            .optional()?;
        Ok(row.flatten())
    }

    /// Set the phone's membership alone, stamping `joined_at_ms` the first
    /// time it joins, as `set_channel_membership` does.
    pub(crate) fn set_channel_joined_phone(
        &self,
        id: &str,
        joined_phone: bool,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(id)?;
        self.connection().execute(
            "UPDATE channel
            SET joined_phone = ?1,
                joined_at_ms = CASE
                    WHEN ?1 = 1 AND joined_at_ms IS NULL THEN ?2 ELSE joined_at_ms
                END
            WHERE id = ?3",
            params![joined_phone, now_ms, id],
        )?;
        Ok(())
    }

    pub(crate) fn set_channel_alias(
        &self,
        id: &str,
        alias: Option<String>,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(id)?;
        self.connection().execute(
            "UPDATE channel SET alias = ? WHERE id = ?",
            params![alias, id],
        )?;
        Ok(())
    }

    pub(crate) fn set_channel_notifications(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(id)?;
        self.connection().execute(
            "UPDATE channel SET notifications_enabled = ? WHERE id = ?",
            params![enabled, id],
        )?;
        Ok(())
    }

    pub(crate) fn set_channel_routing(
        &self,
        id: &str,
        region_code: Option<Vec<u8>>,
        max_flood_hops: Option<u8>,
    ) -> Result<(), MobileStoreError> {
        let id = channel_id(id)?;
        self.connection().execute(
            "UPDATE channel SET region_code = ?, max_flood_hops = ? WHERE id = ?",
            params![region_code, max_flood_hops, id],
        )?;
        Ok(())
    }

    /// Leave a channel, in one erasing transaction: its conversation and
    /// transcript go; a built-in channel's row stays with the phone's flag
    /// cleared, and any other row is deleted. `None` when the identity has
    /// no such channel. The key is the caller's to delete.
    pub(crate) fn leave_channel(
        &self,
        owner_identity_id: &str,
        id: &str,
    ) -> Result<Option<LeftChannel>, MobileStoreError> {
        let id = channel_id(id)?;
        self.erase(|transaction| {
            let Some(kind) = transaction
                .query_row(
                    "SELECT kind FROM channel WHERE owner_identity_id = ? AND id = ?",
                    params![owner_identity_id, id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let conversation_address = transaction
                .query_row(
                    "SELECT conversation_address FROM channel_conversation
                    WHERE owner_identity_id = ? AND channel_id = ?",
                    params![owner_identity_id, id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(address) = &conversation_address {
                purge_conversation_history(transaction, owner_identity_id, address)?;
                transaction.execute(
                    "DELETE FROM channel_conversation
                    WHERE owner_identity_id = ? AND channel_id = ?",
                    params![owner_identity_id, id],
                )?;
            }
            let deleted =
                MobileStoredChannelKind::parse(&kind) != Some(MobileStoredChannelKind::Builtin);
            if deleted {
                transaction.execute("DELETE FROM channel WHERE id = ?", params![id])?;
            } else {
                transaction.execute(
                    "UPDATE channel SET joined_phone = 0 WHERE id = ?",
                    params![id],
                )?;
            }
            Ok(Some(LeftChannel {
                deleted,
                conversation_address,
            }))
        })
    }
}
