//! The application store: one SQLite database, one schema, and one set of
//! queries for both apps.
//!
//! The schema starts where the Swift store's 31 migrations end. A new file
//! gets that schema in one step (`schema_v31.sql`, dumped from the Swift
//! store by `scripts/ios/dump-store-schema.sh`, which CI reruns to keep the
//! two identical). A database the Swift store left at v31 opens as it is.
//! Anything older was last opened by a build that predates the shared store
//! and must be opened once by a build that still migrates in Swift; the
//! Swift migrations are not ported. This store's own migrations start at
//! v32.
//!
//! Instants cross the interface as integer Unix milliseconds. Most columns
//! store them that way (`*_at_ms`, truncated by the caller). Two node
//! columns, `last_heard_at` and `advertisement_received_at`, are REAL Unix
//! seconds, as the Swift store wrote them: they are converted at this
//! boundary and read back rounded to the millisecond.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior};

mod channels;
mod claimed_radios;
mod conversations;
mod management;
mod peers;
mod repeaters;
mod routes;

pub use channels::{MobileStoredChannelKind, MobileStoredChannelRecord};
pub use claimed_radios::{MobileStoredClaimedRadioRecord, claimed_radio_lapse_ms};
pub use conversations::{
    MobileApplicationRecords, MobileStoredChannelConversationRecord,
    MobileStoredConversationPreviewRecord, MobileStoredDirectConversationRecord,
};
pub use management::{MobileStoredCachedPropertyRecord, MobileStoredManagementCardRecord};
pub use peers::{MobilePeerUpsertRecord, MobileStoredNodeRecord};
pub use repeaters::{
    MobileStoredPeerRepeaterEntryRecord, MobileStoredPeerRepeaterListingRecord,
    MobileStoredPeerRepeaterReportRecord,
};
pub use routes::MobileStoredManualRouteRecord;

/// The version the Swift store's migrations end at, and the one a new file
/// starts at.
const BASELINE_VERSION: i64 = 31;

/// The whole schema at [`BASELINE_VERSION`].
const BASELINE: &str = include_str!("schema_v31.sql");

/// One step of this store's own ladder, taking the database from
/// `version - 1` to `version`.
struct Migration {
    version: i64,
    sql: &'static str,
    /// Work SQL cannot express, run after `sql` in the same transaction.
    rewrite: Option<fn(&Connection) -> rusqlite::Result<()>>,
}

/// This store's migrations, in order, starting at v32.
const MIGRATIONS: &[Migration] = &[
    // The prefix-search key moves from Foundation's fold to the store's own,
    // so both platforms write and match the same key.
    Migration {
        version: 32,
        sql: "",
        rewrite: Some(peers::refold_alias_search),
    },
];

/// How long a statement waits on another connection's lock before failing.
const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Why the store could not do what was asked. Carries no input and no SQL:
/// errors reach logs and support bundles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileStoreError {
    /// The file could not be opened or created.
    OpenFailed,
    /// The file holds a schema this store does not read: newer than it
    /// knows, older than the Swift store's last migration, or a database
    /// that is not the application store at all.
    UnsupportedSchema { version: i64 },
    /// The record an update names does not exist.
    RecordNotFound,
    /// An argument is not in the form the store keeps: a channel ID that is
    /// not a UUID.
    InvalidArgument,
    /// SQLite refused an operation.
    Failed,
}

impl MobileStoreError {
    /// Redacted diagnostic code suitable for logs and support bundles.
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::OpenFailed => "STORE_OPEN_FAILED",
            Self::UnsupportedSchema { .. } => "STORE_UNSUPPORTED_SCHEMA",
            Self::RecordNotFound => "STORE_RECORD_NOT_FOUND",
            Self::InvalidArgument => "STORE_INVALID_ARGUMENT",
            Self::Failed => "STORE_FAILED",
        }
    }
}

impl core::fmt::Display for MobileStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.diagnostic_code())
    }
}

impl std::error::Error for MobileStoreError {}

impl From<rusqlite::Error> for MobileStoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Failed
    }
}

/// The application database, behind one connection.
///
/// One connection serves every query, as the Swift store's single
/// serialized connection does today. Calls block on SQLite, so platforms
/// make them off the main thread.
#[derive(uniffi::Object)]
pub struct MobileAppStore {
    connection: Mutex<Connection>,
}

#[uniffi::export]
impl MobileAppStore {
    /// Open the store at `path`, creating it if there is no file, and bring
    /// it to the current schema.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, MobileStoreError> {
        let mut connection = Connection::open(&path).map_err(|_| MobileStoreError::OpenFailed)?;
        configure(&connection)?;
        migrate(&mut connection, MIGRATIONS)?;
        Ok(Arc::new(Self {
            connection: Mutex::new(connection),
        }))
    }

    /// The schema version the database is at.
    pub fn schema_version(&self) -> Result<i64, MobileStoreError> {
        Ok(user_version(&self.connection())?)
    }

    /// Delete every row in every table, in one transaction, leaving the
    /// schema and its version in place so the next open has nothing to
    /// migrate. What identity erasure uses to take the store down with the
    /// key, so every build has it.
    ///
    /// The tables are read from the schema rather than listed here, so a
    /// migration that adds one cannot leave an erasure quietly incomplete.
    /// `sqlite_sequence` is SQLite's own and is left: row IDs carry on from
    /// where they were.
    pub fn erase_all_content(&self) -> Result<(), MobileStoreError> {
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Which order the tables empty in is not something this has to
        // know: with the checks deferred to the commit, the only state the
        // foreign keys are tested against is the final one, where every
        // table is empty and nothing can dangle. That holds for RESTRICT
        // too, which SQLite otherwise checks at once: a `node` row emptied
        // before the `direct_conversation` rows that hold it would refuse.
        // The pragma ends with the transaction.
        transaction.pragma_update(None, "defer_foreign_keys", true)?;
        for table in table_names(&transaction)? {
            transaction.execute(&format!("DELETE FROM \"{table}\""), [])?;
        }
        transaction.commit()?;
        Ok(())
    }
}

impl MobileAppStore {
    fn connection(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves SQLite itself consistent:
        // every write is a transaction that rolls back on drop.
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The connection settings the Swift store uses, in its order.
fn configure(connection: &Connection) -> Result<(), MobileStoreError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
    // An in-memory database answers "memory"; a file must take WAL.
    if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
        return Err(MobileStoreError::Failed);
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    peers::register_functions(connection)?;
    Ok(())
}

/// The database's own tables, in the order the schema lists them.
fn table_names(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?
        .query_map([], |row| row.get(0))?
        .collect()
}

fn user_version(connection: &Connection) -> rusqlite::Result<i64> {
    connection.pragma_query_value(None, "user_version", |row| row.get(0))
}

/// Bring the database to the last version `ladder` reaches, in one
/// transaction, deciding from the version read inside it so two openers
/// cannot both build the schema.
fn migrate(connection: &mut Connection, ladder: &[Migration]) -> Result<i64, MobileStoreError> {
    let current = ladder.last().map_or(BASELINE_VERSION, |step| step.version);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut version = user_version(&transaction)?;
    if version == 0 {
        // A file with no version is new, unless it already holds anything:
        // then it is not this store's.
        let objects: i64 =
            transaction.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
        if objects != 0 {
            return Err(MobileStoreError::UnsupportedSchema { version });
        }
        transaction.execute_batch(BASELINE)?;
        version = BASELINE_VERSION;
    }
    if !(BASELINE_VERSION..=current).contains(&version) {
        return Err(MobileStoreError::UnsupportedSchema { version });
    }
    let start = version;
    for step in ladder.iter().filter(|step| step.version > start) {
        debug_assert_eq!(step.version, version + 1, "migrations must be consecutive");
        transaction.execute_batch(step.sql)?;
        if let Some(rewrite) = step.rewrite {
            rewrite(&transaction)?;
        }
        version = step.version;
    }
    // A database already current is left unwritten: the transaction rolls
    // back on drop.
    if version != user_version(&transaction)? {
        transaction.pragma_update(None, "user_version", version)?;
        transaction.commit()?;
    }
    Ok(version)
}

#[cfg(test)]
mod tests;
