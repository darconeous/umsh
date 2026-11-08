//! Crash-safe, identity-scoped frame-counter boundary persistence.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
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
///
/// Every operation runs on one thread of the store's own, in the order it
/// was asked for: the fsyncs never hold the thread that drives the MAC, and
/// a commit whose caller stopped waiting still lands before any asked for
/// after it, so a newer boundary is never overwritten by an older one. The
/// caller learns that a boundary is durable only from the thread's reply.
#[derive(uniffi::Object)]
pub struct MobileCounterStore {
    jobs: mpsc::Sender<Job>,
    #[cfg(test)]
    files: Arc<CounterFiles>,
}

/// One operation for the commit thread, and where its result goes.
enum Job {
    Load {
        context: Vec<u8>,
        reply: Reply<Result<u32, CounterStoreError>>,
    },
    Commit {
        context: Vec<u8>,
        boundary: u32,
        reply: Reply<Result<(), CounterStoreError>>,
    },
    Flush {
        reply: Reply<Result<(), CounterStoreError>>,
    },
    LoadRecords {
        node: umsh_core::PublicKey,
        reply: Reply<Result<Vec<u8>, CounterStoreError>>,
    },
    KeepRecords {
        node: umsh_core::PublicKey,
        records: Vec<u8>,
        reply: Reply<Result<(), CounterStoreError>>,
    },
}

/// Where a result goes: back to an awaiting task, or to a blocked caller.
enum Reply<T> {
    Await(tokio::sync::oneshot::Sender<T>),
    Block(mpsc::SyncSender<T>),
}

impl<T> Reply<T> {
    fn send(self, value: T) {
        // A caller that stopped waiting learns nothing; the work is done.
        match self {
            Self::Await(reply) => {
                let _ = reply.send(value);
            }
            Self::Block(reply) => {
                let _ = reply.send(value);
            }
        }
    }
}

#[uniffi::export]
impl MobileCounterStore {
    #[uniffi::constructor]
    pub fn new(root_directory: String) -> Result<Arc<Self>, CounterStoreError> {
        let root = PathBuf::from(root_directory);
        if !root.is_absolute() {
            return Err(CounterStoreError::InvalidRootDirectory);
        }
        let files = Arc::new(CounterFiles { root });
        let (jobs, queue) = mpsc::channel();
        let worker = files.clone();
        // The thread ends once the store, and with it the queue's sender,
        // is dropped.
        std::thread::Builder::new()
            .name("umsh-counter-store".to_owned())
            .spawn(move || worker.serve(&queue))
            .map_err(|_| CounterStoreError::IoFailure)?;
        Ok(Arc::new(Self {
            jobs,
            #[cfg(test)]
            files,
        }))
    }

    pub fn load_boundary(&self, context: Vec<u8>) -> Result<u32, CounterStoreError> {
        self.block(|reply| Job::Load { context, reply })?
    }

    pub fn commit_boundary(
        &self,
        context: Vec<u8>,
        boundary: u32,
    ) -> Result<(), CounterStoreError> {
        self.block(|reply| Job::Commit {
            context,
            boundary,
            reply,
        })?
    }
}

impl MobileCounterStore {
    /// The records `node` keeps of its sessions with forward secrecy, as
    /// [`umsh_node::PfsSessionRecord::encode_all`] wrote them: empty when
    /// it keeps none.
    pub(crate) fn load_forward_secrecy_records(
        &self,
        node: &umsh_core::PublicKey,
    ) -> Result<Vec<u8>, CounterStoreError> {
        let node = *node;
        self.block(|reply| Job::LoadRecords { node, reply })?
    }

    /// Keep `records` as everything `node` holds of its sessions with
    /// forward secrecy, as durably as a counter boundary, in turn with the
    /// boundaries.
    pub(crate) fn keep_forward_secrecy_records(
        &self,
        node: &umsh_core::PublicKey,
        records: &[u8],
    ) -> Result<(), CounterStoreError> {
        let node = *node;
        let records = records.to_vec();
        self.block(|reply| Job::KeepRecords {
            node,
            records,
            reply,
        })?
    }

    /// Queue a job and wait on this thread for its result.
    fn block<T>(&self, job: impl FnOnce(Reply<T>) -> Job) -> Result<T, CounterStoreError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.jobs
            .send(job(Reply::Block(reply)))
            .map_err(|_| CounterStoreError::IoFailure)?;
        result.recv().map_err(|_| CounterStoreError::IoFailure)
    }

    /// Queue a job and await its result. Dropping the future leaves the job
    /// queued: it still runs, in its turn.
    async fn queue<T>(&self, job: impl FnOnce(Reply<T>) -> Job) -> Result<T, CounterStoreError> {
        let (reply, result) = tokio::sync::oneshot::channel();
        self.jobs
            .send(job(Reply::Await(reply)))
            .map_err(|_| CounterStoreError::IoFailure)?;
        // A job that never reported is ambiguous, and an ambiguous commit
        // is a failed one.
        result.await.map_err(|_| CounterStoreError::IoFailure)
    }
}

/// The records themselves, touched only by the commit thread.
struct CounterFiles {
    root: PathBuf,
}

impl CounterFiles {
    fn serve(&self, queue: &mpsc::Receiver<Job>) {
        while let Ok(job) = queue.recv() {
            match job {
                Job::Load { context, reply } => reply.send(self.load_boundary_unlocked(&context)),
                Job::Commit {
                    context,
                    boundary,
                    reply,
                } => reply.send(self.commit_boundary_unlocked(&context, boundary, None)),
                Job::Flush { reply } => reply.send(self.flush()),
                Job::LoadRecords { node, reply } => {
                    reply.send(self.load_forward_secrecy_records(&node));
                }
                Job::KeepRecords {
                    node,
                    records,
                    reply,
                } => reply.send(self.keep_forward_secrecy_records(&node, &records)),
            }
        }
    }

    fn flush(&self) -> Result<(), CounterStoreError> {
        if !self.root.exists() {
            return Ok(());
        }
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| CounterStoreError::IoFailure)
    }

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
        self.write_atomically(&destination, &encode_record(boundary), failpoint)
    }

    /// The records `node` keeps of its sessions with forward secrecy, as
    /// [`umsh_node::PfsSessionRecord::encode_all`] wrote them: empty when
    /// it keeps none.
    fn load_forward_secrecy_records(
        &self,
        node: &umsh_core::PublicKey,
    ) -> Result<Vec<u8>, CounterStoreError> {
        match fs::read(self.forward_secrecy_path(node)) {
            Ok(records) => Ok(records),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(CounterStoreError::IoFailure),
        }
    }

    /// Keep `records` as everything `node` holds of its sessions with
    /// forward secrecy, as durably as a counter boundary.
    fn keep_forward_secrecy_records(
        &self,
        node: &umsh_core::PublicKey,
        records: &[u8],
    ) -> Result<(), CounterStoreError> {
        let path = self.forward_secrecy_path(node);
        if !records.is_empty() {
            return self.write_atomically(&path, records, None);
        }
        // Keeping nothing is having no file: nothing is written, and the
        // directory is not made, for a node that never held a session.
        match fs::remove_file(&path) {
            Ok(()) => File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| CounterStoreError::IoFailure),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CounterStoreError::IoFailure),
        }
    }

    /// Beside the counter boundaries, named for the node: only public keys
    /// go in it, never a session's private key.
    fn forward_secrecy_path(&self, node: &umsh_core::PublicKey) -> PathBuf {
        let mut filename = String::with_capacity(node.0.len() * 2 + 4);
        for byte in node.0 {
            use fmt::Write as _;
            write!(&mut filename, "{byte:02x}").expect("writing to String cannot fail");
        }
        filename.push_str(".pfs");
        self.root.join(filename)
    }

    /// Write `record` to a temporary file, synchronize it, rename it over
    /// `destination`, then synchronize the directory.
    fn write_atomically(
        &self,
        destination: &Path,
        record: &[u8],
        failpoint: Option<CommitStage>,
    ) -> Result<(), CounterStoreError> {
        fs::create_dir_all(&self.root).map_err(|_| CounterStoreError::IoFailure)?;
        let temporary = destination.with_extension("pending");

        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| CounterStoreError::IoFailure)?;
            file.write_all(record)
                .map_err(|_| CounterStoreError::IoFailure)?;
            fail_at(failpoint, CommitStage::Written)?;
            file.sync_all().map_err(|_| CounterStoreError::IoFailure)?;
            fail_at(failpoint, CommitStage::FileSynced)?;
            drop(file);

            fs::rename(&temporary, destination).map_err(|_| CounterStoreError::IoFailure)?;
            fail_at(failpoint, CommitStage::Renamed)?;
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
        let context = context.to_vec();
        self.queue(|reply| Job::Load { context, reply }).await?
    }

    async fn store(&self, context: &[u8], value: u32) -> Result<(), Self::Error> {
        let context = context.to_vec();
        self.queue(|reply| Job::Commit {
            context,
            boundary: value,
            reply,
        })
        .await?
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        self.queue(|reply| Job::Flush { reply }).await?
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
    Written,
    FileSynced,
    Renamed,
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
        for stage in [CommitStage::Written, CommitStage::FileSynced] {
            let (_directory, store) = store();
            store.commit_boundary(b"primary".to_vec(), 128).unwrap();
            assert_eq!(
                store
                    .files
                    .commit_boundary_unlocked(b"primary", 256, Some(stage)),
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
            store
                .files
                .commit_boundary_unlocked(b"primary", 256, Some(CommitStage::Renamed)),
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
        fs::create_dir_all(&store.files.root).unwrap();
        fs::write(store.files.record_path(b"primary").unwrap(), b"partial").unwrap();
        assert_eq!(
            store.load_boundary(b"primary".to_vec()),
            Err(CounterStoreError::CorruptRecord)
        );
    }

    /// Commits land in the order they were asked for, including those whose
    /// callers stopped waiting: an older boundary never lands over a newer
    /// one, and every load sees the commits asked for before it.
    #[tokio::test]
    async fn commits_land_in_order_even_when_abandoned() {
        use umsh_hal::CounterStore as _;
        let (_directory, store) = store();
        for step in 1..=40u32 {
            let commit = store.store(b"primary", step * 128);
            if step % 2 == 1 {
                // Polled once, which queues it, then dropped.
                let _ = tokio::time::timeout(std::time::Duration::ZERO, commit).await;
            } else {
                commit.await.unwrap();
                assert_eq!(store.load(b"primary").await.unwrap(), step * 128);
            }
        }
        // One abandoned last, then a load: the load waits its turn.
        let _ = tokio::time::timeout(std::time::Duration::ZERO, store.store(b"primary", 41 * 128))
            .await;
        assert_eq!(store.load(b"primary").await.unwrap(), 41 * 128);
        assert_eq!(store.load_boundary(b"primary".to_vec()).unwrap(), 41 * 128);
    }

    #[test]
    fn implements_hal_counter_store_contract() {
        fn assert_counter_store<T: umsh_hal::CounterStore>() {}
        assert_counter_store::<MobileCounterStore>();
    }
}
