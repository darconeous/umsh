//! Crash-safe, identity-scoped frame-counter boundary persistence.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

const FILE_MAGIC: &[u8; 4] = b"UMCT";
const FILE_VERSION: u8 = 1;
const RECORD_LEN: usize = 16;
const MAX_CONTEXT_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Error)]
pub enum CounterStoreError {
    InvalidRootDirectory,
    InvalidContext,
    CorruptRecord,
    IoFailure,
}

impl CounterStoreError {
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::InvalidRootDirectory => "COUNTER_ROOT_INVALID",
            Self::InvalidContext => "COUNTER_CONTEXT_INVALID",
            Self::CorruptRecord => "COUNTER_RECORD_CORRUPT",
            Self::IoFailure => "COUNTER_IO_FAILURE",
        }
    }
}

impl fmt::Display for CounterStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.diagnostic_code())
    }
}

impl std::error::Error for CounterStoreError {}

/// Durable adapter used by the iOS `umsh_hal::CounterStore` boundary.
///
/// Each commit writes and synchronizes a temporary record, atomically renames
/// it over the previous boundary, then synchronizes the containing directory.
/// An error at any stage is treated as ambiguous by the caller and therefore
/// cannot release a prepared authenticated frame for transmission.
#[derive(uniffi::Object)]
pub struct MobileCounterStore {
    root: PathBuf,
    operation_lock: Mutex<()>,
}

#[uniffi::export]
impl MobileCounterStore {
    #[uniffi::constructor]
    pub fn new(root_directory: String) -> Result<Arc<Self>, CounterStoreError> {
        let root = PathBuf::from(root_directory);
        if !root.is_absolute() {
            return Err(CounterStoreError::InvalidRootDirectory);
        }
        Ok(Arc::new(Self {
            root,
            operation_lock: Mutex::new(()),
        }))
    }

    pub fn load_boundary(&self, context: Vec<u8>) -> Result<u32, CounterStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| CounterStoreError::IoFailure)?;
        self.load_boundary_unlocked(&context)
    }

    pub fn commit_boundary(
        &self,
        context: Vec<u8>,
        boundary: u32,
    ) -> Result<(), CounterStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| CounterStoreError::IoFailure)?;
        self.commit_boundary_unlocked(&context, boundary, None)
    }
}

impl MobileCounterStore {
    fn load_boundary_unlocked(&self, context: &[u8]) -> Result<u32, CounterStoreError> {
        let path = self.record_path(context)?;
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(_) => return Err(CounterStoreError::IoFailure),
        };
        let mut record = Vec::new();
        file.read_to_end(&mut record)
            .map_err(|_| CounterStoreError::IoFailure)?;
        decode_record(&record)
    }

    fn commit_boundary_unlocked(
        &self,
        context: &[u8],
        boundary: u32,
        failpoint: Option<CommitStage>,
    ) -> Result<(), CounterStoreError> {
        let destination = self.record_path(context)?;
        fs::create_dir_all(&self.root).map_err(|_| CounterStoreError::IoFailure)?;
        let temporary = destination.with_extension("pending");
        let record = encode_record(boundary);

        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| CounterStoreError::IoFailure)?;
            file.write_all(&record)
                .map_err(|_| CounterStoreError::IoFailure)?;
            fail_at(failpoint, CommitStage::AfterWrite)?;
            file.sync_all().map_err(|_| CounterStoreError::IoFailure)?;
            fail_at(failpoint, CommitStage::AfterFileSync)?;
            drop(file);

            fs::rename(&temporary, &destination).map_err(|_| CounterStoreError::IoFailure)?;
            fail_at(failpoint, CommitStage::AfterRename)?;
            File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| CounterStoreError::IoFailure)?;
            Ok(())
        })();

        if result.is_err() && temporary.exists() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn record_path(&self, context: &[u8]) -> Result<PathBuf, CounterStoreError> {
        validate_context(context)?;
        let mut filename = String::with_capacity(context.len() * 2 + 4);
        for byte in context {
            use fmt::Write as _;
            write!(&mut filename, "{byte:02x}").expect("writing to String cannot fail");
        }
        filename.push_str(".ctr");
        Ok(self.root.join(filename))
    }
}

impl umsh_hal::CounterStore for MobileCounterStore {
    type Error = CounterStoreError;

    async fn load(&self, context: &[u8]) -> Result<u32, Self::Error> {
        self.load_boundary(context.to_vec())
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        self.commit_boundary(context.to_vec(), value)
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| CounterStoreError::IoFailure)?;
        if !self.root.exists() {
            return Ok(());
        }
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CounterStoreError::IoFailure)
    }
}

fn validate_context(context: &[u8]) -> Result<(), CounterStoreError> {
    if context.is_empty() || context.len() > MAX_CONTEXT_LEN {
        Err(CounterStoreError::InvalidContext)
    } else {
        Ok(())
    }
}

fn encode_record(boundary: u32) -> [u8; RECORD_LEN] {
    let mut record = [0u8; RECORD_LEN];
    record[..4].copy_from_slice(FILE_MAGIC);
    record[4] = FILE_VERSION;
    record[8..12].copy_from_slice(&boundary.to_be_bytes());
    let checksum = checksum(&record[..12]);
    record[12..].copy_from_slice(&checksum.to_be_bytes());
    record
}

fn decode_record(record: &[u8]) -> Result<u32, CounterStoreError> {
    if record.len() != RECORD_LEN
        || &record[..4] != FILE_MAGIC
        || record[4] != FILE_VERSION
        || record[5..8] != [0, 0, 0]
    {
        return Err(CounterStoreError::CorruptRecord);
    }
    let expected = u32::from_be_bytes(record[12..16].try_into().unwrap());
    if checksum(&record[..12]) != expected {
        return Err(CounterStoreError::CorruptRecord);
    }
    Ok(u32::from_be_bytes(record[8..12].try_into().unwrap()))
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    AfterWrite,
    AfterFileSync,
    AfterRename,
}

fn fail_at(requested: Option<CommitStage>, current: CommitStage) -> Result<(), CounterStoreError> {
    if requested == Some(current) {
        Err(CounterStoreError::IoFailure)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Arc<MobileCounterStore>) {
        let directory = tempfile::tempdir().unwrap();
        let store =
            MobileCounterStore::new(directory.path().join("counters").display().to_string())
                .unwrap();
        (directory, store)
    }

    #[test]
    fn missing_context_starts_at_zero_and_commits_boundary() {
        let (_directory, store) = store();
        assert_eq!(store.load_boundary(b"primary".to_vec()).unwrap(), 0);
        store.commit_boundary(b"primary".to_vec(), 128).unwrap();
        assert_eq!(store.load_boundary(b"primary".to_vec()).unwrap(), 128);
    }

    #[test]
    fn failures_before_rename_preserve_previous_boundary() {
        for stage in [CommitStage::AfterWrite, CommitStage::AfterFileSync] {
            let (_directory, store) = store();
            store.commit_boundary(b"primary".to_vec(), 128).unwrap();
            assert_eq!(
                store.commit_boundary_unlocked(b"primary", 256, Some(stage)),
                Err(CounterStoreError::IoFailure)
            );
            assert_eq!(store.load_boundary(b"primary".to_vec()).unwrap(), 128);
        }
    }

    #[test]
    fn ambiguous_failure_after_rename_recovers_new_boundary() {
        let (directory, store) = store();
        store.commit_boundary(b"primary".to_vec(), 128).unwrap();
        assert_eq!(
            store.commit_boundary_unlocked(b"primary", 256, Some(CommitStage::AfterRename)),
            Err(CounterStoreError::IoFailure)
        );

        let reopened =
            MobileCounterStore::new(directory.path().join("counters").display().to_string())
                .unwrap();
        assert_eq!(reopened.load_boundary(b"primary".to_vec()).unwrap(), 256);
    }

    #[test]
    fn corrupt_or_invalid_records_fail_closed() {
        let (_directory, store) = store();
        assert_eq!(
            store.load_boundary(Vec::new()),
            Err(CounterStoreError::InvalidContext)
        );
        fs::create_dir_all(&store.root).unwrap();
        fs::write(store.record_path(b"primary").unwrap(), b"partial").unwrap();
        assert_eq!(
            store.load_boundary(b"primary".to_vec()),
            Err(CounterStoreError::CorruptRecord)
        );
    }

    #[test]
    fn implements_hal_counter_store_contract() {
        fn assert_counter_store<T: umsh_hal::CounterStore>() {}
        assert_counter_store::<MobileCounterStore>();
    }
}
