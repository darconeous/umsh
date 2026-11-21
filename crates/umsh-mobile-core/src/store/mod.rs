//! The application store: one SQLite database, one schema, and one set of
//! queries for both apps.
//!
//! The schema starts where the Swift store's 31 migrations ended. A new file
//! gets that schema in one step (`schema_v31.sql`, dumped from the Swift
//! store before iOS moved onto this one). A database the Swift store left at
//! v31 opens as it is. Anything older is refused: the Swift migrations were
//! not ported, so such a file needs one run of a build that still has them.
//! This store's own migrations start at v32.
//!
//! Instants are integer Unix milliseconds (`*_at_ms`, truncated by the
//! caller), in the columns and across the interface.
//!
//! Every write of more than one statement goes through
//! [`MobileAppStore::write`], and every read of more than one through
//! [`MobileAppStore::read`], so each is one transaction.
//!
//! A stored value its field cannot hold is handled by what the field is,
//! never by wrapping it into range:
//!
//! - A row whose identity cannot be read (a channel ID that is not a UUID,
//!   a kind this build does not know) is left out of a list.
//! - A count with bounds (a hop limit, a signal figure a router reported)
//!   saturates at them.
//! - An optional figure or reference (a message's wire coordinates, what
//!   the radio measured, what a reply answers) reads as absent.
//! - Anything else, a key column above all, fails the read.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, Transaction, TransactionBehavior};

mod channels;
mod chat;
mod chat_batch;
mod claimed_radios;
mod conversations;
mod management;
mod peers;
mod repeaters;
mod routes;
mod staging;
mod transcript;

pub use channels::{MobileStoredChannelKind, MobileStoredChannelRecord};
pub use chat::{
    MobileStoredChatDeliveryFailureRecord, MobileStoredChatDeliveryState,
    MobileStoredChatMessageRefRecord, MobileStoredChatNotificationTargetRecord,
    MobileStoredChatReactionNotificationTargetRecord,
};
pub(crate) use chat_batch::{ChatBatchContext, ChatBatchEffects};
pub use chat_batch::{MobileChatChangesRecord, MobileChatNotificationRecord};
pub use claimed_radios::{MobileStoredClaimedRadioRecord, claimed_radio_lapse_ms};
pub use conversations::{
    MobileApplicationRecords, MobileStoredChannelConversationRecord,
    MobileStoredConversationPreviewRecord, MobileStoredDirectConversationRecord,
};
pub use management::{MobileStoredCachedPropertyRecord, MobileStoredManagementCardRecord};
pub use peers::{
    MobilePeerUpsertRecord, MobileStoredNodeKind, MobileStoredNodeRecord, MobileStoredSystemRole,
};
pub use repeaters::{
    MobileStoredPeerRepeaterEntryRecord, MobileStoredPeerRepeaterListingRecord,
    MobileStoredPeerRepeaterReportRecord,
};
pub use routes::MobileStoredManualRouteRecord;
pub use staging::{
    MobileStagedChatMessageRecord, MobileStagedChatReactionRecord, MobileStagedChatRegarding,
};
pub use transcript::{
    MobileStoredChatCursorRecord, MobileStoredChatMessagePageRecord, MobileStoredChatMessageRecord,
    MobileStoredChatQuoteRecord, MobileStoredChatQuotedMessageRecord,
    MobileStoredChatReactionRecord, MobileStoredChatReceptionRecord, MobileStoredChatRepeatsRecord,
};

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
}

/// This store's migrations, in order, starting at v32.
const MIGRATIONS: &[Migration] = &[Migration {
    version: 32,
    sql: include_str!("migration_v32.sql"),
}];

/// How long a statement waits on another connection's lock before failing.
const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Why the store could not do what was asked.
///
/// Errors reach logs and support bundles, so none carries what a caller
/// passed in or the text or bytes a row holds.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileStoreError {
    /// The file could not be opened or created. `code` is SQLite's extended
    /// result code.
    OpenFailed { code: i32 },
    /// The file holds a schema this store does not read: newer than it
    /// knows, older than the Swift store's last migration, or a database
    /// that is not the application store at all.
    UnsupportedSchema { version: i64 },
    /// The record an update names does not exist.
    RecordNotFound,
    /// An argument is not in the form the store keeps: a channel ID that is
    /// not a UUID, a router hint that is not two octets.
    InvalidArgument,
    /// SQLite refused an operation, or a row did not read as its columns
    /// are declared.
    ///
    /// `code` is SQLite's extended result code, or 0 when the failure was
    /// in reading a row. `detail` is SQLite's own account, which names the
    /// table, column, or constraint: the code alone says only that
    /// something was refused.
    Failed { code: i32, detail: String },
}

impl MobileStoreError {
    /// Redacted diagnostic code suitable for logs and support bundles.
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::OpenFailed { .. } => "STORE_OPEN_FAILED",
            Self::UnsupportedSchema { .. } => "STORE_UNSUPPORTED_SCHEMA",
            Self::RecordNotFound => "STORE_RECORD_NOT_FOUND",
            Self::InvalidArgument => "STORE_INVALID_ARGUMENT",
            Self::Failed { .. } => "STORE_FAILED",
        }
    }
}

impl core::fmt::Display for MobileStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.diagnostic_code())?;
        match self {
            Self::OpenFailed { code } => write!(formatter, " ({code})"),
            Self::UnsupportedSchema { version } => write!(formatter, " (v{version})"),
            Self::Failed { code, detail } => write!(formatter, " ({code}): {detail}"),
            Self::RecordNotFound | Self::InvalidArgument => Ok(()),
        }
    }
}

impl std::error::Error for MobileStoreError {}

impl From<rusqlite::Error> for MobileStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Failed {
            code: sqlite_code(&error),
            detail: match error {
                rusqlite::Error::SqliteFailure(failure, detail) => {
                    detail.unwrap_or_else(|| failure.to_string())
                }
                other => other.to_string(),
            },
        }
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
    /// Bumped by every write to the channel rows the app core derives its
    /// channel cache from: a channel added or deleted, the phone joining
    /// or leaving one, or its details changed. Not by the core's own
    /// `joined_device` writes, which the cache does not read. The core
    /// compares it to catch such a write it was not told of.
    content_writes: AtomicU64,
}

#[uniffi::export]
impl MobileAppStore {
    /// Open the store at `path`, creating it if there is no file, and bring
    /// it to the current schema.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, MobileStoreError> {
        let mut connection =
            Connection::open(&path).map_err(|error| MobileStoreError::OpenFailed {
                code: sqlite_code(&error),
            })?;
        // Set first, so the version check below waits out a lock as every
        // later statement does.
        connection.busy_timeout(BUSY_TIMEOUT)?;
        // A file this build cannot open is refused before any setting that
        // writes to it: switching to WAL rewrites the file's header.
        openable_version(&connection, ladder_top(MIGRATIONS))?;
        configure(&connection)?;
        migrate(&mut connection, MIGRATIONS)?;
        Ok(Arc::new(Self {
            connection: Mutex::new(connection),
            content_writes: AtomicU64::new(0),
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
        self.erase(|transaction| {
            // Which order the tables empty in is not something this has to
            // know: with the checks deferred to the commit, the only state the
            // foreign keys are tested against is the final one, where every
            // table is empty and nothing can dangle. That holds for RESTRICT
            // too, which SQLite otherwise checks at once: a `node` row emptied
            // before the `direct_conversation` rows that hold it would refuse.
            // The pragma ends with the transaction.
            transaction.pragma_update(None, "defer_foreign_keys", true)?;
            for table in table_names(transaction)? {
                transaction.execute(&format!("DELETE FROM \"{table}\""), [])?;
            }
            Ok(())
        })
    }
}

/// Moves the content write count when dropped.
struct ContentWrite<'a>(&'a AtomicU64);

impl Drop for ContentWrite<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

impl MobileAppStore {
    /// How many writes to the channel rows the app core's channel cache
    /// derives from have been asked for.
    pub(crate) fn content_writes(&self) -> u64 {
        self.content_writes.load(Ordering::Acquire)
    }

    /// Count a write the app core's channel cache derives from. The count
    /// moves when the returned guard drops, after the write: a reader
    /// that reads the count before the rows then never records a count
    /// whose write it has not seen.
    fn wrote_content(&self) -> ContentWrite<'_> {
        ContentWrite(&self.content_writes)
    }

    fn connection(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves SQLite itself consistent:
        // every write is a transaction that rolls back on drop.
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Run `work` as one write transaction: committed when it returns `Ok`,
    /// rolled back when it fails. The write lock is taken at the start, so
    /// what `work` reads is what it then writes over.
    fn write<T>(
        &self,
        work: impl FnOnce(&Transaction<'_>) -> Result<T, MobileStoreError>,
    ) -> Result<T, MobileStoreError> {
        self.transact(TransactionBehavior::Immediate, work)
    }

    /// A write that erases content the user asked to be rid of. With
    /// `secure_delete` on, the rows it deletes are overwritten in the
    /// database; the checkpoint after it moves that into the file and
    /// empties the write-ahead log, which still holds the old pages.
    fn erase<T>(
        &self,
        work: impl FnOnce(&Transaction<'_>) -> Result<T, MobileStoreError>,
    ) -> Result<T, MobileStoreError> {
        let value = self.write(work)?;
        // The erase itself is committed; a checkpoint another connection's
        // reader holds back is retried by the next one, so it is logged
        // rather than failed.
        if let Err(error) = self
            .connection()
            .pragma_update(None, "wal_checkpoint", "TRUNCATE")
        {
            log::warn!("erase: the write-ahead log was not checkpointed: {error}");
        }
        Ok(value)
    }

    /// Run `work` as one read transaction, so its statements all see the
    /// database as of the same moment whatever another connection writes
    /// meanwhile.
    fn read<T>(
        &self,
        work: impl FnOnce(&Transaction<'_>) -> Result<T, MobileStoreError>,
    ) -> Result<T, MobileStoreError> {
        self.transact(TransactionBehavior::Deferred, work)
    }

    fn transact<T>(
        &self,
        behavior: TransactionBehavior,
        work: impl FnOnce(&Transaction<'_>) -> Result<T, MobileStoreError>,
    ) -> Result<T, MobileStoreError> {
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(behavior)?;
        let value = work(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }
}

/// SQLite's extended result code for a failure, or 0 for one that did not
/// come from SQLite.
fn sqlite_code(error: &rusqlite::Error) -> i32 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => failure.extended_code,
        _ => 0,
    }
}

/// The connection settings the Swift store used, less the busy timeout,
/// which `open` sets before its first read.
fn configure(connection: &Connection) -> Result<(), MobileStoreError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
    // An in-memory database answers "memory"; a file must take WAL.
    if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
        return Err(MobileStoreError::Failed {
            code: 0,
            detail: format!("journal mode is {mode}, not wal"),
        });
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    // Deleted content is overwritten, not left in free pages. The SQLite
    // Android bundles is built with it off, and Apple's only zeroes what
    // costs no extra I/O.
    connection.pragma_update(None, "secure_delete", true)?;
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
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut version = openable_version(&transaction, ladder_top(ladder))?;
    if version == 0 {
        transaction.execute_batch(BASELINE)?;
        version = BASELINE_VERSION;
    }
    let start = version;
    for step in ladder.iter().filter(|step| step.version > start) {
        debug_assert_eq!(step.version, version + 1, "migrations must be consecutive");
        transaction.execute_batch(step.sql)?;
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

/// The version the last step of `ladder` leaves a file at.
fn ladder_top(ladder: &[Migration]) -> i64 {
    ladder.last().map_or(BASELINE_VERSION, |step| step.version)
}

/// The version a file is at, when a build whose ladder ends at `current`
/// can open it: 0 for a new file, or a version from the baseline to
/// `current`. Only reads.
fn openable_version(connection: &Connection, current: i64) -> Result<i64, MobileStoreError> {
    let version = user_version(connection)?;
    if version == 0 {
        // A file with no version is new, unless it already holds anything:
        // then it is not this store's.
        let objects: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
        if objects != 0 {
            return Err(MobileStoreError::UnsupportedSchema { version });
        }
    } else if !(BASELINE_VERSION..=current).contains(&version) {
        return Err(MobileStoreError::UnsupportedSchema { version });
    }
    Ok(version)
}

/// A stored count narrowed to its field's type, saturating at the type's
/// bounds.
fn clamp<T: TryFrom<i64> + Bounded>(value: i64) -> T {
    T::try_from(value).unwrap_or(if value < 0 { T::MIN } else { T::MAX })
}

trait Bounded {
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

/// A stored optional figure narrowed to its field's type: absent when the
/// type cannot hold it.
fn narrowed<T: TryFrom<i64>>(value: Option<i64>) -> Option<T> {
    value.and_then(|value| T::try_from(value).ok())
}

#[cfg(test)]
mod chat_test_support;
#[cfg(test)]
mod tests;
