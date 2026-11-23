//! Paths the person chose for a node (`node_manual_route`), each held until
//! an instant and hung from the node's row.
//!
//! A path's repeater hints are fixed-width and ordered, so they store as one
//! blob of the hints back to back rather than as a table of their own. A
//! direct path is an empty blob, never NULL.

use rusqlite::{Connection, OptionalExtension, params};

use super::peers::node_id;
use super::{MobileAppStore, MobileStoreError, clamp};

/// The width of one repeater hint in a stored path.
const HINT_WIDTH: usize = 2;

/// A path the person chose for one node, held until `hold_until_ms`.
///
/// Instants are Unix milliseconds.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct MobileStoredManualRouteRecord {
    pub public_address: String,
    /// Two-byte repeater hints, in send order. None is a direct path.
    pub hints: Vec<Vec<u8>>,
    /// How far the path floods past its last repeater.
    pub flood_hops: u8,
    pub hold_until_ms: i64,
    /// Where the phone stood when the path was saved, if it knew.
    pub saved_latitude: Option<f64>,
    pub saved_longitude: Option<f64>,
    /// Horizontal accuracy of that fix, in meters.
    pub saved_accuracy: Option<f64>,
    /// The offer to switch to a learned path was declined.
    pub prompt_settled: bool,
}

#[uniffi::export]
impl MobileAppStore {
    /// The path held for one node, or `None` when none is held at `now_ms`.
    /// A path whose hold has ended reads as none but is left in place;
    /// `manual_routes` is what forgets it.
    pub fn manual_route(
        &self,
        owner_identity_id: String,
        public_address: String,
        now_ms: i64,
    ) -> Result<Option<MobileStoredManualRouteRecord>, MobileStoreError> {
        Ok(self
            .connection()
            .query_row(
                &format!(
                    "SELECT {ROUTE_COLUMNS}
                    FROM node_manual_route r JOIN node n ON n.id = r.node_id
                    WHERE n.owner_identity_id = ? AND n.public_address = ?
                        AND r.hold_until_ms > ?"
                ),
                params![owner_identity_id, public_address, now_ms],
                stored_route,
            )
            .optional()?)
    }

    /// Every path still held at `now_ms`, forgetting, in the same
    /// transaction, those whose hold has ended. In no particular order.
    pub fn manual_routes(
        &self,
        owner_identity_id: String,
        now_ms: i64,
    ) -> Result<Vec<MobileStoredManualRouteRecord>, MobileStoreError> {
        self.write(|transaction| {
            transaction.execute(
                "DELETE FROM node_manual_route
                WHERE hold_until_ms <= ?
                    AND node_id IN (SELECT id FROM node WHERE owner_identity_id = ?)",
                params![now_ms, owner_identity_id],
            )?;
            let routes = held_routes(transaction, &owner_identity_id)?;
            Ok(routes)
        })
    }

    /// Hold `hints` for one node until `hold_until_ms`, replacing any path
    /// held for it. A new path is a new choice, so a declined offer to
    /// switch away from the old one does not carry over. A node with no row
    /// has nowhere to keep it, and the call does nothing.
    ///
    /// The hints are stored back to back, so each must be two octets, the
    /// width a stored path is read back in: any other width, a node's
    /// three-octet hint say, would read back as a different path, and
    /// fails with [`MobileStoreError::InvalidArgument`].
    #[allow(clippy::too_many_arguments)]
    pub fn save_manual_route(
        &self,
        owner_identity_id: String,
        public_address: String,
        hints: Vec<Vec<u8>>,
        flood_hops: u8,
        hold_until_ms: i64,
        latitude: Option<f64>,
        longitude: Option<f64>,
        accuracy: Option<f64>,
    ) -> Result<(), MobileStoreError> {
        if hints.iter().any(|hint| hint.len() != HINT_WIDTH) {
            return Err(MobileStoreError::InvalidArgument);
        }
        self.write(|transaction| {
            let Some(node_id) = node_id(transaction, &owner_identity_id, &public_address)? else {
                return Ok(());
            };
            transaction.execute(
                "INSERT OR REPLACE INTO node_manual_route (
                    node_id, hints, hold_until_ms, saved_latitude, saved_longitude,
                    saved_accuracy, prompt_settled, flood_hops
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                params![
                    node_id,
                    // An empty path binds as an empty blob, which the column
                    // needs: it refuses NULL.
                    hints.concat(),
                    hold_until_ms,
                    latitude,
                    longitude,
                    accuracy,
                    flood_hops,
                ],
            )?;
            Ok(())
        })
    }

    /// Forget the path held for one node, if any.
    pub fn clear_manual_route(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "DELETE FROM node_manual_route WHERE node_id IN (
                SELECT id FROM node WHERE owner_identity_id = ? AND public_address = ?
            )",
            params![owner_identity_id, public_address],
        )?;
        Ok(())
    }

    /// Remember that the offer to switch away from this node's path was
    /// declined, so it is not made again for the same path.
    pub fn settle_manual_route_prompt(
        &self,
        owner_identity_id: String,
        public_address: String,
    ) -> Result<(), MobileStoreError> {
        self.connection().execute(
            "UPDATE node_manual_route SET prompt_settled = 1 WHERE node_id IN (
                SELECT id FROM node WHERE owner_identity_id = ? AND public_address = ?
            )",
            params![owner_identity_id, public_address],
        )?;
        Ok(())
    }
}

/// The route columns, in the order [`stored_route`] reads them.
const ROUTE_COLUMNS: &str = "n.public_address, r.hints, r.hold_until_ms, r.saved_latitude,
    r.saved_longitude, r.saved_accuracy, r.prompt_settled, r.flood_hops";

fn held_routes(
    connection: &Connection,
    owner_identity_id: &str,
) -> Result<Vec<MobileStoredManualRouteRecord>, MobileStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT {ROUTE_COLUMNS}
        FROM node_manual_route r JOIN node n ON n.id = r.node_id
        WHERE n.owner_identity_id = ?"
    ))?;
    let routes = statement
        .query_map(params![owner_identity_id], stored_route)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(routes)
}

fn stored_route(row: &rusqlite::Row<'_>) -> rusqlite::Result<MobileStoredManualRouteRecord> {
    Ok(MobileStoredManualRouteRecord {
        public_address: row.get(0)?,
        hints: unpack_hints(&row.get::<_, Vec<u8>>(1)?),
        hold_until_ms: row.get(2)?,
        saved_latitude: row.get(3)?,
        saved_longitude: row.get(4)?,
        saved_accuracy: row.get(5)?,
        prompt_settled: row.get::<_, i64>(6)? != 0,
        flood_hops: clamp(row.get(7)?),
    })
}

/// A stored path's hints. A trailing octet short of a whole hint is nothing
/// a hint could be and is left out.
fn unpack_hints(packed: &[u8]) -> Vec<Vec<u8>> {
    packed
        .as_chunks::<HINT_WIDTH>()
        .0
        .iter()
        .map(|hint| hint.to_vec())
        .collect()
}

#[cfg(test)]
mod tests;
