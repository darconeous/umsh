//! What routers have reported about their neighbors: per router, a
//! listing header (`node_peer_repeaters`) and its entries
//! (`node_peer_repeater_entry`), both hung from the router's `node` row and
//! gone with it.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::peers::node_id;
use super::{MobileAppStore, MobileStoreError};

/// One neighbor a router reported, as the page carried it.
///
/// Stored decoded rather than as the wire entry: the fields are few and
/// fixed, the map reads them without a decoder in the loop, and the location
/// arrives from the core already reduced to a center and a precision.
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileStoredPeerRepeaterEntryRecord {
    /// Two or three bytes; the row's key within the router's listing.
    pub hint: Vec<u8>,
    pub name: Option<String>,
    pub rssi_dbm: Option<i16>,
    pub snr_quarter_db: Option<i16>,
    pub last_heard_minutes: Option<u16>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub location_precision: Option<u8>,
    /// Two octets per code, as the wire carries them.
    pub region_codes: Vec<Vec<u8>>,
    /// When the page naming this neighbor was answered.
    pub reported_at_ms: i64,
}

/// A neighbor entry with the row of the router that reported it.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileStoredPeerRepeaterReportRecord {
    /// The reporting router's `node` row ID.
    pub reporter_node_id: i64,
    pub entry: MobileStoredPeerRepeaterEntryRecord,
}

/// What a router last said about its neighbors, as far as this phone asked.
///
/// The cursor is kept so the next open can carry on where the last page
/// stopped rather than starting the listing over: the ask is the operator's
/// to make, and the cache should make it cheap to make the right one.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileStoredPeerRepeaterListingRecord {
    /// In the order the router listed them.
    pub entries: Vec<MobileStoredPeerRepeaterEntryRecord>,
    /// How many neighbors the whole listing holds, when a page said.
    pub total: Option<i64>,
    /// The cursor for the page after the last one held; absent once the
    /// listing is complete.
    pub next_cursor: Option<Vec<u8>>,
    /// When the latest page was answered, Unix milliseconds.
    pub as_of_ms: i64,
}

#[uniffi::export]
impl MobileAppStore {
    /// Every neighbor any router has reported to this phone, with the row
    /// of the router that said so, by router and then in listing order.
    /// What the map draws.
    pub fn all_peer_repeater_entries(
        &self,
        owner_identity_id: String,
    ) -> Result<Vec<MobileStoredPeerRepeaterReportRecord>, MobileStoreError> {
        all_peer_repeater_entries(&self.connection(), &owner_identity_id)
    }

    /// What a router last said about its neighbors, or `None` when it was
    /// never asked. Entries come back in the order the router listed them.
    /// The header and the entries are read in one transaction, so a page
    /// saved meanwhile cannot pair one page's cursor with another's entries.
    pub fn peer_repeater_listing(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<Option<MobileStoredPeerRepeaterListingRecord>, MobileStoreError> {
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(node_id) = node_id(&transaction, &owner_identity_id, &public_address)? else {
            return Ok(None);
        };
        let Some((total, next_cursor, as_of_ms)) = transaction
            .query_row(
                "SELECT total, next_cursor, as_of_ms FROM node_peer_repeaters WHERE node_id = ?",
                params![node_id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let entries = {
            let mut statement = transaction.prepare(&format!(
                "SELECT {} FROM node_peer_repeater_entry e
                WHERE e.node_id = ?
                ORDER BY e.position",
                entry_columns()
            ))?;
            statement
                .query_map(params![node_id], |row| stored_entry(row, 0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        transaction.commit()?;
        Ok(Some(MobileStoredPeerRepeaterListingRecord {
            entries,
            total,
            next_cursor,
            as_of_ms,
        }))
    }

    /// Record one page of a router's neighbor listing, answered at `at_ms`.
    ///
    /// A page asked for without a cursor (`replacing`) is the top of a fresh
    /// listing and replaces whatever was held. A page that followed a cursor
    /// is added to it: new neighbors take their place at the end, and a
    /// neighbor the router named again—the responder restarts a listing
    /// whose table has moved under a stale cursor—updates in place rather
    /// than appearing twice. Either way the total, the cursor, and the
    /// instant are the latest page's. A router with no row has nowhere to
    /// keep the page, and the call does nothing.
    ///
    /// Stored as the Swift store wrote it: region codes back to back, with
    /// none stored as NULL, and an empty cursor stored as no cursor. An
    /// entry with an empty hint is refused by the column with
    /// [`MobileStoreError::Failed`], and the page with it.
    #[allow(clippy::too_many_arguments)]
    pub fn save_peer_repeater_page(
        &self,
        owner_identity_id: String,
        public_address: String,
        entries: Vec<MobileStoredPeerRepeaterEntryRecord>,
        total: Option<i64>,
        next_cursor: Option<Vec<u8>>,
        replacing: bool,
        at_ms: i64,
    ) -> Result<(), MobileStoreError> {
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(node_id) = node_id(&transaction, &owner_identity_id, &public_address)? else {
            return Ok(());
        };
        if replacing {
            transaction.execute(
                "DELETE FROM node_peer_repeater_entry WHERE node_id = ?",
                params![node_id],
            )?;
        }
        transaction.execute(
            "INSERT INTO node_peer_repeaters (node_id, total, next_cursor, as_of_ms)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                total = excluded.total,
                next_cursor = excluded.next_cursor,
                as_of_ms = excluded.as_of_ms",
            params![node_id, total, blob_or_null(next_cursor), at_ms],
        )?;
        let mut position: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM node_peer_repeater_entry
            WHERE node_id = ?",
            params![node_id],
            |row| row.get(0),
        )?;
        {
            // A repeated hint keeps the position it already holds; only the
            // figures move. `excluded.position` would shuffle it to the end.
            let mut upsert = transaction.prepare(
                "INSERT INTO node_peer_repeater_entry (
                    node_id, hint, position, name, rssi_dbm, snr_quarter_db,
                    last_heard_min, latitude, longitude, location_precision,
                    region_codes, reported_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, hint) DO UPDATE SET
                    name = excluded.name,
                    rssi_dbm = excluded.rssi_dbm,
                    snr_quarter_db = excluded.snr_quarter_db,
                    last_heard_min = excluded.last_heard_min,
                    latitude = excluded.latitude,
                    longitude = excluded.longitude,
                    location_precision = excluded.location_precision,
                    region_codes = excluded.region_codes,
                    reported_at_ms = excluded.reported_at_ms",
            )?;
            for entry in entries {
                upsert.execute(params![
                    node_id,
                    blob_or_null(Some(entry.hint)),
                    position,
                    entry.name,
                    entry.rssi_dbm,
                    entry.snr_quarter_db,
                    entry.last_heard_minutes,
                    entry.latitude,
                    entry.longitude,
                    entry.location_precision,
                    blob_or_null(Some(entry.region_codes.concat())),
                    entry.reported_at_ms,
                ])?;
                position += 1;
            }
        }
        transaction.commit()?;
        Ok(())
    }
}

pub(super) fn all_peer_repeater_entries(
    connection: &Connection,
    owner_identity_id: &str,
) -> Result<Vec<MobileStoredPeerRepeaterReportRecord>, MobileStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT e.node_id, {}
        FROM node_peer_repeater_entry e JOIN node n ON n.id = e.node_id
        WHERE n.owner_identity_id = ?
        ORDER BY e.node_id, e.position",
        entry_columns()
    ))?;
    let reports = statement
        .query_map(params![owner_identity_id], |row| {
            Ok(MobileStoredPeerRepeaterReportRecord {
                reporter_node_id: row.get(0)?,
                entry: stored_entry(row, 1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(reports)
}

/// The entry columns of `node_peer_repeater_entry e`, in the order
/// [`stored_entry`] reads them.
fn entry_columns() -> &'static str {
    "e.hint, e.name, e.rssi_dbm, e.snr_quarter_db, e.last_heard_min, e.latitude,
    e.longitude, e.location_precision, e.region_codes, e.reported_at_ms"
}

/// The entry a row holds in [`entry_columns`] order, starting at `offset`.
fn stored_entry(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<MobileStoredPeerRepeaterEntryRecord> {
    Ok(MobileStoredPeerRepeaterEntryRecord {
        hint: row.get::<_, Option<Vec<u8>>>(offset)?.unwrap_or_default(),
        name: row.get(offset + 1)?,
        rssi_dbm: row.get::<_, Option<i64>>(offset + 2)?.map(clamp),
        snr_quarter_db: row.get::<_, Option<i64>>(offset + 3)?.map(clamp),
        last_heard_minutes: row.get::<_, Option<i64>>(offset + 4)?.map(clamp),
        latitude: row.get(offset + 5)?,
        longitude: row.get(offset + 6)?,
        location_precision: row.get::<_, Option<i64>>(offset + 7)?.map(clamp),
        region_codes: region_codes(row.get(offset + 8)?),
        reported_at_ms: row.get(offset + 9)?,
    })
}

/// A blob as the Swift store bound it: its binding gave an empty blob no
/// address, which SQLite takes as NULL. Kept so both stores write the same
/// rows.
fn blob_or_null(value: Option<Vec<u8>>) -> Option<Vec<u8>> {
    value.filter(|bytes| !bytes.is_empty())
}

/// The packed `region_codes` column as its two-octet codes. A trailing odd
/// octet is nothing a code could be and is left out.
fn region_codes(packed: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    packed
        .unwrap_or_default()
        .chunks_exact(2)
        .map(<[u8]>::to_vec)
        .collect()
}

/// A stored integer narrowed to its field's type, saturating at the type's
/// bounds rather than wrapping.
pub(super) fn clamp<T: TryFrom<i64> + Bounded>(value: i64) -> T {
    T::try_from(value).unwrap_or(if value < 0 { T::MIN } else { T::MAX })
}

pub(super) trait Bounded {
    const MIN: Self;
    const MAX: Self;
}

macro_rules! bounded {
    ($($type:ty),*) => {$(
        impl Bounded for $type {
            const MIN: Self = <$type>::MIN;
            const MAX: Self = <$type>::MAX;
        }
    )*};
}

bounded!(u8, u16, i16);

#[cfg(test)]
mod tests;
