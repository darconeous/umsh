//! What this phone has learned about remote devices through node
//! management: each device's card (`node_mgmt_card`) and the property values
//! it last reported (`node_prop_cache`), both hung from the device's `node`
//! row and gone with it.
//!
//! A device with no `node` row has nowhere to keep either, so writes about
//! one are quietly dropped and reads find nothing: nothing is cached about a
//! stranger.

use std::collections::HashMap;

use rusqlite::types::Value;
use rusqlite::{OptionalExtension, params, params_from_iter};

use super::peers::node_id;
use super::{MobileAppStore, MobileStoreError};

/// What a remote device said it is, kept between openings of its settings.
///
/// The four things worth learning once: a device's capabilities and firmware
/// version change only when it is reflashed, its hardware never, and its name
/// rarely. Holding them means a later open of a device's settings puts
/// nothing on the air at all. Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MobileStoredManagementCardRecord {
    /// `PROP_CAPS` verbatim, planned against without asking the device
    /// again.
    pub capabilities: Vec<u8>,
    /// `PROP_DEV_VERSION`. The key the cached values hang from: different
    /// firmware may hold different properties, so a change here discards
    /// them.
    pub device_version: Option<String>,
    pub device_model: Option<String>,
    pub device_name: Option<String>,
    pub fetched_at_ms: i64,
}

/// One property as a device last reported it, and when.
///
/// The value is the octets that came off the air: what they mean is settled
/// by the ULCP decoders rather than here, so a value cached by one build
/// reads the same in the next. The instant (Unix milliseconds) is what lets
/// a screen date a reading rather than present it as current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MobileStoredCachedPropertyRecord {
    pub value: Vec<u8>,
    pub fetched_at_ms: i64,
}

impl MobileAppStore {
    /// What a device last said it is, if this phone has ever asked.
    pub fn management_card(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<Option<MobileStoredManagementCardRecord>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                "SELECT c.capabilities, c.device_version, c.device_model, c.device_name,
                    c.fetched_at_ms
                FROM node_mgmt_card c JOIN node n ON n.id = c.node_id
                WHERE n.owner_identity_id = ? AND n.public_address = ?",
                params![owner_identity_id, public_address],
                |row| {
                    Ok(MobileStoredManagementCardRecord {
                        capabilities: row.get(0)?,
                        device_version: row.get(1)?,
                        device_model: row.get(2)?,
                        device_name: row.get(3)?,
                        fetched_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Record what a card read found.
    ///
    /// A device running different firmware is a device whose capabilities,
    /// property set, and defaults may all have moved, so everything cached
    /// about the old firmware is dropped in the same transaction. Nothing
    /// about a cached value says which firmware produced it, and a value
    /// that outlives its firmware is worse than no value: it prefills a form
    /// with a plausible reading nobody can date. A first card has nothing to
    /// supersede, so values cached before it stay.
    pub fn save_management_card(
        &self,
        owner_identity_id: String,
        public_address: String,
        card: MobileStoredManagementCardRecord,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            let Some(node_id) = node_id(transaction, &owner_identity_id, &public_address)? else {
                return Ok(());
            };
            let known_version = transaction
                .query_row(
                    "SELECT device_version FROM node_mgmt_card WHERE node_id = ?",
                    params![node_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?;
            // Absent and absent are the same firmware; absent and a version are
            // not.
            if known_version.is_some_and(|known| known != card.device_version) {
                transaction.execute(
                    "DELETE FROM node_prop_cache WHERE node_id = ?",
                    params![node_id],
                )?;
            }
            transaction.execute(
                "INSERT INTO node_mgmt_card (
                    node_id, capabilities, device_version, device_model, device_name,
                    fetched_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    capabilities = excluded.capabilities,
                    device_version = excluded.device_version,
                    device_model = excluded.device_model,
                    device_name = excluded.device_name,
                    fetched_at_ms = excluded.fetched_at_ms",
                params![
                    node_id,
                    // Empty capabilities are an empty blob, not NULL: the
                    // column refuses NULL.
                    card.capabilities,
                    card.device_version,
                    card.device_model,
                    card.device_name,
                    card.fetched_at_ms,
                ],
            )?;
            Ok(())
        })
    }

    /// Forget everything cached about a device, so the next open asks it
    /// afresh. The card goes too: a refresh that cannot be trusted to be
    /// about the same firmware is not a refresh.
    pub fn forget_management_cache(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<(), MobileStoreError> {
        self.write(|transaction| {
            let Some(node_id) = node_id(transaction, &owner_identity_id, &public_address)? else {
                return Ok(());
            };
            for table in ["node_prop_cache", "node_mgmt_card"] {
                transaction.execute(
                    &format!("DELETE FROM {table} WHERE node_id = ?"),
                    params![node_id],
                )?;
            }
            Ok(())
        })
    }

    /// What a device was last seen configured as, for the properties asked
    /// for. Absent properties are simply not in the result: never fetched
    /// and refused read the same from here, and a screen shows both as a
    /// field it has nothing to prefill.
    pub fn cached_properties(
        &self,
        owner_identity_id: String,
        public_address: String,
        property_ids: Vec<u32>,
    ) -> Result<HashMap<u32, MobileStoredCachedPropertyRecord>, MobileStoreError> {
        if property_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = vec!["?"; property_ids.len()].join(", ");
        let connection = self.connection();
        let mut statement = connection.prepare(&format!(
            "SELECT p.property_id, p.value, p.fetched_at_ms
            FROM node_prop_cache p JOIN node n ON n.id = p.node_id
            WHERE n.owner_identity_id = ? AND n.public_address = ?
                AND p.property_id IN ({placeholders})"
        ))?;
        let arguments = [Value::Text(owner_identity_id), Value::Text(public_address)]
            .into_iter()
            .chain(property_ids.into_iter().map(|id| Value::Integer(id.into())));
        let cached = statement
            .query_map(params_from_iter(arguments), |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    MobileStoredCachedPropertyRecord {
                        value: row.get(1)?,
                        fetched_at_ms: row.get(2)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()?;
        Ok(cached)
    }

    /// Record values a device reported—from a read, or from the echo a
    /// write comes back with, which is the freshest statement of what the
    /// device is actually holding. Every value takes `at_ms`. An empty value
    /// is kept as one: a property can be empty.
    pub fn save_cached_properties(
        &self,
        owner_identity_id: String,
        public_address: String,
        values: HashMap<u32, Vec<u8>>,
        at_ms: i64,
    ) -> Result<(), MobileStoreError> {
        if values.is_empty() {
            return Ok(());
        }
        self.write(|transaction| {
            let Some(node_id) = node_id(transaction, &owner_identity_id, &public_address)? else {
                return Ok(());
            };
            {
                let mut upsert = transaction.prepare(
                    "INSERT INTO node_prop_cache (node_id, property_id, value, fetched_at_ms)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(node_id, property_id) DO UPDATE SET
                        value = excluded.value,
                        fetched_at_ms = excluded.fetched_at_ms",
                )?;
                for (property_id, value) in &values {
                    upsert.execute(params![node_id, property_id, value, at_ms])?;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
