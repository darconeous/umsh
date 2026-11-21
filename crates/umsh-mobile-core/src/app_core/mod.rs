//! `MobileAppCore`: the application layer both apps share, over one store
//! for its whole life.
//!
//! Queries never wait on the worker. They read the store and the published
//! snapshot, which the core replaces behind a leaf lock. A change flag is
//! raised only after the snapshot that reflects it is published, so a query
//! made on the wake sees it.
//!
//! This landing has the reads: the queries, the owner they read for, and a
//! lifecycle without a session (idle, stopping, stopped).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};

use crate::MobileError;
use crate::mobile_mesh::{UpdateListener, WakeSignal};
use crate::store::{MobileAppStore, MobileStoreError};

mod mapping;
#[cfg(test)]
mod parity;
mod queries;
mod records;
#[cfg(test)]
mod tests;

pub use records::{
    MobileAppChangesRecord, MobileAppChannelConversationRecord, MobileAppChannelPreviewRecord,
    MobileAppChannelRecord, MobileAppDirectConversationRecord, MobileAppLifecycle,
    MobileAppMessageRecord, MobileAppMessageRepeaterRecord, MobileAppNeighborReportRecord,
    MobileAppPeerRecord, MobileAppPreviewRecord, MobileAppRepeaterListingRecord,
    MobileAppRepeaterNeighborRecord, MobileAppStateRecord, MobileAppStatusRecord,
    MobileAppTranscriptPageRecord,
};

/// Why the core could not answer.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileAppError {
    /// The store failed the read or write.
    Store { error: MobileStoreError },
    /// An argument does not parse: an address, a channel invitation.
    InvalidInput { error: MobileError },
    /// No owner is set, so there is nobody to read for.
    NoOwner,
    /// The core is stopping.
    Busy,
    /// The core has stopped.
    Stopped,
}

impl std::fmt::Display for MobileAppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store { error } => error.fmt(formatter),
            Self::InvalidInput { error } => error.fmt(formatter),
            Self::NoOwner => formatter.write_str("no owner is set"),
            Self::Busy => formatter.write_str("the core is busy"),
            Self::Stopped => formatter.write_str("the core has stopped"),
        }
    }
}

impl std::error::Error for MobileAppError {}

impl From<MobileStoreError> for MobileAppError {
    fn from(error: MobileStoreError) -> Self {
        Self::Store { error }
    }
}

impl From<MobileError> for MobileAppError {
    fn from(error: MobileError) -> Self {
        Self::InvalidInput { error }
    }
}

/// Told that `poll_changes` has something new.
///
/// Called on whichever thread published the change; implementations only
/// schedule a drain on their own executor and return. Calls are coalesced:
/// one per pending-to-drained cycle.
#[uniffi::export(with_foreign)]
pub trait MobileAppCoreListener: Send + Sync {
    fn on_changes_pending(&self);
}

impl UpdateListener for dyn MobileAppCoreListener {
    fn update_pending(&self) {
        self.on_changes_pending();
    }
}

/// The wall clock, which tests replace.
pub(crate) trait Clock: Send + Sync {
    /// Unix milliseconds.
    fn now_ms(&self) -> i64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            })
    }
}

/// What queries read besides the store.
#[derive(Clone, Debug)]
struct Snapshot {
    lifecycle: MobileAppLifecycle,
    /// Whose rows the queries read.
    owner: Option<String>,
    /// The attached radio's address, while it carries this phone as its
    /// host.
    attached_host: Option<String>,
    unknown_device_channels: Vec<Vec<u8>>,
}

/// What the object and its worker share.
struct Shared {
    snapshot: Mutex<Snapshot>,
    changes: Mutex<MobileAppChangesRecord>,
    wake: WakeSignal<dyn MobileAppCoreListener>,
}

impl Shared {
    fn snapshot(&self) -> MutexGuard<'_, Snapshot> {
        self.snapshot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Apply `change` to the snapshot, then raise what it reports. The
    /// snapshot's lock is released before the flags go up and the listener
    /// is called.
    fn publish(&self, change: impl FnOnce(&mut Snapshot) -> MobileAppChangesRecord) {
        let raised = change(&mut self.snapshot());
        if raised == MobileAppChangesRecord::default() {
            return;
        }
        self.changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .merge(raised);
        self.wake.notify();
    }

    /// Move the lifecycle to `next`, reporting it.
    fn enter(&self, next: MobileAppLifecycle) {
        self.publish(|snapshot| {
            if snapshot.lifecycle == next {
                return MobileAppChangesRecord::default();
            }
            snapshot.lifecycle = next;
            MobileAppChangesRecord {
                lifecycle: Some(next),
                ..MobileAppChangesRecord::default()
            }
        });
    }
}

/// Requests from the object to its worker.
enum WorkerCommand {
    Stop,
}

/// The application core.
#[derive(uniffi::Object)]
pub struct MobileAppCore {
    store: Arc<MobileAppStore>,
    clock: Arc<dyn Clock>,
    shared: Arc<Shared>,
    /// Dropping the object closes this, which ends the worker as `stop`
    /// does, without waiting for it.
    commands: mpsc::UnboundedSender<WorkerCommand>,
    /// Becomes true when the worker has ended.
    finished: watch::Receiver<bool>,
}

#[uniffi::export]
impl MobileAppCore {
    /// A core over `store`, which native code opened and keeps using: both
    /// share its one connection.
    #[uniffi::constructor]
    pub fn new(store: Arc<MobileAppStore>) -> Result<Arc<Self>, MobileAppError> {
        Self::with_clock(store, Arc::new(SystemClock))
    }

    pub fn set_listener(&self, listener: Arc<dyn MobileAppCoreListener>) {
        self.shared.wake.set_listener(Some(listener));
    }

    pub fn clear_listener(&self) {
        self.shared.wake.set_listener(None);
    }

    /// What changed since the last call. Answers in every state, so the
    /// last lifecycle change is never lost.
    pub fn poll_changes(&self) -> MobileAppChangesRecord {
        // Re-armed first, so a change published mid-drain wakes again.
        self.shared.wake.drained();
        std::mem::take(
            &mut *self
                .shared
                .changes
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Whose rows the queries read, or nobody's. Kept in every state but
    /// stopped. Raises every list's change flag, since each now reads
    /// differently.
    pub fn set_owner(&self, owner_identity_id: Option<String>) -> Result<(), MobileAppError> {
        let mut refused = None;
        self.shared.publish(|snapshot| {
            if snapshot.lifecycle == MobileAppLifecycle::Stopped {
                refused = Some(MobileAppError::Stopped);
                return MobileAppChangesRecord::default();
            }
            snapshot.owner = owner_identity_id;
            MobileAppChangesRecord {
                lifecycle: None,
                peers_changed: true,
                channels_changed: true,
                conversations_changed: true,
            }
        });
        refused.map_or(Ok(()), Err)
    }

    pub fn status(&self) -> Result<MobileAppStatusRecord, MobileAppError> {
        let lifecycle = self.shared.snapshot().lifecycle;
        match lifecycle {
            MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
            lifecycle => Ok(MobileAppStatusRecord { lifecycle }),
        }
    }

    /// Finish the core. It resolves once the worker has ended; a second
    /// call waits for the same end, and a call on a stopped core does
    /// nothing.
    pub async fn stop(&self) {
        let mut stopping = false;
        self.shared.publish(|snapshot| {
            if snapshot.lifecycle != MobileAppLifecycle::Idle {
                return MobileAppChangesRecord::default();
            }
            stopping = true;
            snapshot.lifecycle = MobileAppLifecycle::Stopping;
            MobileAppChangesRecord {
                lifecycle: Some(MobileAppLifecycle::Stopping),
                ..MobileAppChangesRecord::default()
            }
        });
        if stopping {
            // A worker already gone has published its end.
            let _ = self.commands.send(WorkerCommand::Stop);
        }
        let mut finished = self.finished.clone();
        // The worker's sender goes with it, which ends the wait too.
        let _ = finished.wait_for(|finished| *finished).await;
    }
}

impl MobileAppCore {
    pub(crate) fn with_clock(
        store: Arc<MobileAppStore>,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, MobileAppError> {
        let shared = Arc::new(Shared {
            snapshot: Mutex::new(Snapshot {
                lifecycle: MobileAppLifecycle::Idle,
                owner: None,
                attached_host: None,
                unknown_device_channels: Vec::new(),
            }),
            changes: Mutex::new(MobileAppChangesRecord::default()),
            wake: WakeSignal::new(),
        });
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (finished_tx, finished) = watch::channel(false);
        let worker_shared = shared.clone();
        std::thread::Builder::new()
            .name("umsh-app-core".to_owned())
            .spawn(move || run_worker(&worker_shared, command_rx, &finished_tx))
            .map_err(|_| MobileAppError::Stopped)?;
        Ok(Arc::new(Self {
            store,
            clock,
            shared,
            commands,
            finished,
        }))
    }

    /// The owner to read for, when the lifecycle allows a query.
    fn reader(&self) -> Result<String, MobileAppError> {
        let snapshot = self.shared.snapshot();
        match snapshot.lifecycle {
            MobileAppLifecycle::Idle => snapshot.owner.clone().ok_or(MobileAppError::NoOwner),
            MobileAppLifecycle::Stopping => Err(MobileAppError::Busy),
            MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
        }
    }
}

/// The worker: a current-thread runtime with a `LocalSet`, where the
/// core's own work runs. It ends on `Stop`, or when the object is dropped
/// and its sender with it.
fn run_worker(
    shared: &Shared,
    mut commands: mpsc::UnboundedReceiver<WorkerCommand>,
    finished: &watch::Sender<bool>,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build();
    if let Ok(runtime) = runtime {
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async {
            // Stop is the only command yet, so the first one, or the
            // sender closing, ends the worker.
            match commands.recv().await {
                Some(WorkerCommand::Stop) | None => {}
            }
        });
    }
    shared.enter(MobileAppLifecycle::Stopped);
    finished.send_replace(true);
}
