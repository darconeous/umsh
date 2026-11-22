//! Bringing one of a device's key tables to a desired set: what to take
//! out and what to put in, and the edits that do it.

use std::collections::BTreeSet;

use super::carrier::Carrier;
use super::operation::Operation;
use super::records::MobileKeyTable;
use super::refusal::Stop;
use crate::app_core::worker::Worker;

/// The edits that turn one key table into another.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyTableDiff {
    /// Keys to take out, in byte order.
    pub(crate) removals: Vec<Vec<u8>>,
    /// Keys to put in, in byte order.
    pub(crate) additions: Vec<Vec<u8>>,
}

impl KeyTableDiff {
    pub(crate) fn is_empty(&self) -> bool {
        self.removals.is_empty() && self.additions.is_empty()
    }

    /// The edits that still change `current`, and the table they leave
    /// it, in byte order.
    pub(crate) fn against(&self, current: &[Vec<u8>]) -> (KeyTableDiff, Vec<Vec<u8>>) {
        let held: BTreeSet<&Vec<u8>> = current.iter().collect();
        let edits = KeyTableDiff {
            removals: self
                .removals
                .iter()
                .filter(|key| held.contains(key))
                .cloned()
                .collect(),
            additions: self
                .additions
                .iter()
                .filter(|key| !held.contains(key))
                .cloned()
                .collect(),
        };
        let mut table: BTreeSet<Vec<u8>> = current.iter().cloned().collect();
        for key in &edits.removals {
            table.remove(key);
        }
        table.extend(edits.additions.iter().cloned());
        (edits, table.into_iter().collect())
    }
}

/// What turns `current` into `desired`, as sets: repeated keys count
/// once.
pub(crate) fn key_table_diff(current: &[Vec<u8>], desired: &[Vec<u8>]) -> KeyTableDiff {
    let current: BTreeSet<&Vec<u8>> = current.iter().collect();
    let desired: BTreeSet<&Vec<u8>> = desired.iter().collect();
    KeyTableDiff {
        removals: current
            .difference(&desired)
            .map(|key| (*key).clone())
            .collect(),
        additions: desired
            .difference(&current)
            .map(|key| (*key).clone())
            .collect(),
    }
}

/// Make `diff`'s edits, removals first: a full table takes a removal but
/// not an addition. The first failure stops the rest.
pub(super) async fn apply_key_table(
    carrier: &Carrier,
    worker: &Worker,
    operation: &Operation,
    table: MobileKeyTable,
    diff: &KeyTableDiff,
) -> Result<(), Stop> {
    for key in &diff.removals {
        carrier
            .table_edit(worker, operation, table, key.clone(), false)
            .await?;
    }
    for key in &diff.additions {
        carrier
            .table_edit(worker, operation, table, key.clone(), true)
            .await?;
    }
    Ok(())
}
