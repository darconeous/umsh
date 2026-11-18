//! Radios that took this phone's identity as their host and have not been
//! seen to let it go (`claimed_radio`).

use rusqlite::{TransactionBehavior, params};

use super::{MobileAppStore, MobileStoreError};

/// How long a claimed-radio record outlives the phone's last attach, in
/// milliseconds: the device lease runs this long from detach, so after it
/// the radio has stood down on its own.
const LAPSE_MS: i64 = 12 * 60 * 60 * 1_000;

/// A radio that took this phone's identity as its host and has not been
/// seen to let it go.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileStoredClaimedRadioRecord {
    /// The radio's device address.
    pub device_address: String,
    pub name: Option<String>,
    /// The last time this phone was attached to it.
    pub attached_at_ms: i64,
}

/// How long a claimed-radio record lasts after the last attach, in
/// milliseconds. A record attached at least this long before now has
/// lapsed.
#[uniffi::export]
pub fn claimed_radio_lapse_ms() -> i64 {
    LAPSE_MS
}

#[uniffi::export]
impl MobileAppStore {
    /// Note that this phone is attached to the radio at `device_address` as
    /// its host, as of `now_ms`, replacing any earlier record of it.
    pub fn record_claimed_radio(
        &self,
        owner_identity_id: String,
        device_address: String,
        name: Option<String>,
        now_ms: i64,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "INSERT OR REPLACE INTO claimed_radio (
                owner_identity_id, device_address, name, attached_at_ms
            ) VALUES (?, ?, ?, ?)",
            params![owner_identity_id, device_address, name, now_ms],
        )?;
        Ok(())
    }

    /// Every radio still recorded as holding this identity, most recent
    /// first, forgetting in the same transaction those whose record has
    /// lapsed by `now_ms`.
    pub fn claimed_radios(
        &self,
        owner_identity_id: String,
        now_ms: i64,
    ) -> Result<Vec<MobileStoredClaimedRadioRecord>, MobileStoreError> {
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM claimed_radio WHERE owner_identity_id = ? AND attached_at_ms <= ?",
            params![owner_identity_id, now_ms.saturating_sub(LAPSE_MS)],
        )?;
        let radios = {
            let mut statement = transaction.prepare(
                "SELECT device_address, name, attached_at_ms FROM claimed_radio
                WHERE owner_identity_id = ?
                ORDER BY attached_at_ms DESC",
            )?;
            statement
                .query_map(params![owner_identity_id], |row| {
                    Ok(MobileStoredClaimedRadioRecord {
                        device_address: row.get(0)?,
                        name: row.get(1)?,
                        attached_at_ms: row.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        transaction.commit()?;
        Ok(radios)
    }

    /// Forget the record of a radio: it let go of this identity, or is no
    /// longer holding it.
    pub fn clear_claimed_radio(
        &self,
        owner_identity_id: String,
        device_address: String,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "DELETE FROM claimed_radio WHERE owner_identity_id = ? AND device_address = ?",
            params![owner_identity_id, device_address],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
