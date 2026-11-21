//! A core over a fresh store, for the tests of everything past the reads.

use std::sync::Arc;
use std::time::Duration;

use super::clock::manual::ManualClock;
use super::{MobileAppConfigRecord, MobileAppCore, MobileAppLifecycle, Options};
use crate::secret_vault::memory::MemoryVault;
use crate::store::MobileAppStore;
use crate::{MobileIdentity, PublicIdentityRecord};

pub(super) const NOW_MS: i64 = 1_790_000_000_000;

pub(super) struct Core {
    pub(super) directory: tempfile::TempDir,
    pub(super) store: Arc<MobileAppStore>,
    pub(super) vault: Arc<MemoryVault>,
    pub(super) clock: Arc<ManualClock>,
    pub(super) core: Arc<MobileAppCore>,
}

impl Core {
    pub(super) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = MobileAppStore::open(directory.path().join("app.sqlite").display().to_string())
            .unwrap();
        let vault = Arc::new(MemoryVault::default());
        let clock = Arc::new(ManualClock::new(NOW_MS));
        let core = MobileAppCore::with_parts(
            store.clone(),
            vault.clone(),
            MobileAppConfigRecord {
                counter_directory: directory.path().join("counters").display().to_string(),
                platform_model: 0,
            },
            clock.clone(),
            Options::default(),
        )
        .unwrap();
        Self {
            directory,
            store,
            vault,
            clock,
            core,
        }
    }

    pub(super) fn counter_directory(&self) -> std::path::PathBuf {
        self.directory.path().join("counters")
    }

    /// Start `seed`'s identity, and answer with its public identity.
    pub(super) async fn start(&self, seed: u8) -> PublicIdentityRecord {
        let identity = identity(seed);
        let public = identity.public_identity();
        self.core.start(identity).await.unwrap();
        assert_eq!(self.lifecycle(), MobileAppLifecycle::Running);
        public
    }

    pub(super) fn lifecycle(&self) -> MobileAppLifecycle {
        self.core.shared.snapshot().lifecycle
    }

    /// Wait, in real time, until `done` holds of the core.
    pub(super) async fn until(&self, what: &str, mut done: impl FnMut(&MobileAppCore) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !done(&self.core) {
            assert!(tokio::time::Instant::now() < deadline, "never: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

pub(super) fn identity(seed: u8) -> Arc<MobileIdentity> {
    MobileIdentity::unlock(vec![seed; 32]).unwrap()
}
