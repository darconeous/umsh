//! `MobileAppCore`: the application layer both apps share, over one store
//! for its whole life.
//!
//! Queries never wait on the worker. They read the store and the published
//! snapshot, which the core replaces behind a leaf lock. A change flag is
//! raised only after the snapshot that reflects it is published, so a query
//! made on the wake sees it.
//!
//! Everything else runs on the worker (see `worker`): `start`, `erase`,
//! `stop` and `use_radio` change the session and the radio in turn, and
//! commands run as tasks beside the pipeline and the policy pass.

use std::future::Future;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{mpsc, oneshot, watch};

use crate::mobile_mesh::{UpdateListener, WakeSignal};
use crate::radio_driver::{MobileRadioDriver, MobileRadioStateRecord};
use crate::secret_vault::{SecretVault, SecretVaultError};
use crate::store::{MobileAppStore, MobileStoreError};
use crate::{MobileError, MobileIdentity, MobileMeshError};

#[cfg(test)]
mod air_tests;
mod bootstrap;
mod channel_commands;
mod channels;
mod chat;
#[cfg(test)]
mod chat_tests;
mod clock;
#[cfg(test)]
mod command_tests;
mod commands;
mod lifecycle;
#[cfg(test)]
mod lifecycle_tests;
mod limits;
mod manage;
mod mapping;
#[cfg(test)]
mod parity;
mod peers;
mod pipeline;
mod policy;
mod queries;
mod records;
mod routes;
mod settings;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
mod waiters;
mod worker;

pub use chat::{MobileAppChatRequest, MobileAppResent, MobileReaction, radio_carries_this_phone};
pub(crate) use clock::Clock;
use clock::SystemClock;
pub use commands::{MobileAppPingReplyRecord, MobileAppPingResult};
pub(crate) use limits::DEFAULT_LOCATION_PRECISION;
pub use limits::{MobileLimitsRecord, mobile_limits};
pub use manage::{
    MobileAnnouncementReach, MobileApplyOutcome, MobileApplyResult, MobileApplyWarning,
    MobileBluetoothDraft, MobileBridgeDraft, MobileCategoryReadingRecord, MobileChoiceField,
    MobileChoiceList, MobileDeviceSetup, MobileDeviceSetupRecord, MobileDraftDetails,
    MobileDraftKind, MobileDraftReviewRecord, MobileFieldProblem, MobileFieldProblemRecord,
    MobileGnssDraft, MobileHeardNetworkRecord, MobileIdentityDraft, MobileIntegerField,
    MobileKeyEntryRecord, MobileKeyListField, MobileKeyTable, MobileKeyTableRecord,
    MobileManagedDevice, MobileManagedDeviceRecord, MobileManagementDraft, MobileManagementLink,
    MobileManagementOutcome, MobileManagementProblem, MobileMeshCoreDraft, MobileNetworkDraft,
    MobileOfferedCategoryRecord, MobileOptionalIntegerField, MobilePositionField,
    MobilePropertyRefusalRecord, MobilePropertyState, MobilePropertyStateRecord,
    MobilePropertyValueRecord, MobileRadioDraft, MobileRefusal, MobileRefusalReason,
    MobileRegionEntryProblem, MobileRepeaterDraft, MobileSetupApplyOutcome,
    MobileSetupChoicesRecord, MobileSetupCompanionRecord, MobileSetupDraft, MobileSetupGoal,
    MobileSetupNote, MobileSetupProfile, MobileSetupProfileGap, MobileSetupRadioParameter,
    MobileSetupRefusal, MobileSetupResult, MobileSetupReviewRecord, MobileSetupSection,
    MobileSetupSetting, MobileSetupUnreadable, MobileTemperatureNames, MobileTemperatureRowRecord,
    MobileTemperatureSummaryRecord, MobileTemperatureValue, MobileTextField, MobileTextListField,
    MobileTimeDraft, MobileToggleField, MobileWifiDraft, MobileWifiEntryCheckRecord,
    MobileWifiEntryProblem, MobileWifiJoinPlanRecord, MobileWifiOutcome, MobileWifiRefusal,
    MobileWifiStep, draft_add_meshcore_region, draft_add_repeater_region, draft_adopt_preset,
    draft_adopt_regions, draft_clear_position, draft_place, draft_place_from_phone,
    draft_set_precision, setup_adopt_preset, setup_set_radio_parameter, wifi_edit_plan,
    wifi_entry_check, wifi_join_plan, wifi_offered_modes,
};
pub use records::{
    MobileAppChangesRecord, MobileAppChannelConversationRecord, MobileAppChannelPreviewRecord,
    MobileAppChannelRecord, MobileAppConfigRecord, MobileAppDirectConversationRecord,
    MobileAppJoinedChannelRecord, MobileAppLifecycle, MobileAppMessageRecord,
    MobileAppMessageRepeaterRecord, MobileAppNeighborReportRecord, MobileAppPeerRecord,
    MobileAppPreviewRecord, MobileAppRepeaterListingRecord, MobileAppRepeaterNeighborRecord,
    MobileAppStartFailure, MobileAppStateRecord, MobileAppStatusRecord,
    MobileAppTranscriptPageRecord, MobileMessageActionsRecord, MobileNotificationEventRecord,
    MobileNotificationReactionRecord, MobileRepeaterEvidence,
};
pub use routes::{
    MobileAppDiscoveryVantageRecord, MobileAppLearnedPathOffer, MobileAppPositionReading,
    MobileAppRouteCandidateRecord, MobileAppRouteRecord,
};
pub use settings::{MobileAppPolicyRecord, MobilePositionRecord};
use worker::{Job, Signals, Worker, WorkerParts};

/// Why the core could not answer.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum MobileAppError {
    /// The store failed the read or write.
    Store { error: MobileStoreError },
    /// An argument does not parse: an address, a channel invitation.
    InvalidInput { error: MobileError },
    /// The request cannot be made as asked: a key of the wrong length, a
    /// path the session cannot carry, a request too large to send, a peer
    /// a conversation still holds, a setting the protocol fixes, or an
    /// unnarrowed ask for identities inside the discovery cooldown
    /// (`discovery_wait_ms`).
    InvalidRequest,
    /// The peer, channel or conversation a command names is not stored.
    NotFound,
    /// The phone's session holds as many channels as it can.
    ChannelTableFull,
    /// No owner is set, so there is nobody to read for.
    NoOwner,
    /// The core is starting, erasing or stopping.
    Busy,
    /// The core has stopped.
    Stopped,
    /// No identity is running.
    NotRunning,
    /// `start` failed, for the reason the lifecycle also reports.
    StartFailed { reason: MobileAppStartFailure },
    /// The vault failed.
    Vault { error: SecretVaultError },
    /// `erase` could not remove the counter reservations.
    CountersNotRemoved,
    /// No radio is attached.
    NoRadio,
    /// The attached radio is not this phone's.
    NotThisPhone,
    /// Nothing answered in time.
    NoAnswer,
    /// The device could not be reached.
    Unreachable,
    /// The device's answer could not be read.
    Unreadable,
    /// The operation was cancelled.
    Cancelled,
    /// The session could not send.
    SendFailed,
    /// The device cannot enter firmware update.
    DfuUnsupported,
    /// The device refused firmware update, with its status.
    DfuRefused { status: u32 },
    /// The device did not confirm entering firmware update.
    DfuUnconfirmed,
    /// The conversation is `EMERGENCY`'s, and its warning has not been
    /// agreed to under this owner (`certify_emergency`).
    EmergencyNotCertified,
    /// The message was kept, but could not go out. `recorded`, it is
    /// stored as not delivered; otherwise that could not be stored either,
    /// and it may read as sending until the next start. The only error a
    /// chat command answers after keeping a message.
    MessageNotQueued { recorded: bool },
}

impl std::fmt::Display for MobileAppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store { error } => error.fmt(formatter),
            Self::InvalidInput { error } => error.fmt(formatter),
            Self::InvalidRequest => formatter.write_str("the request cannot be made as asked"),
            Self::NotFound => formatter.write_str("not stored"),
            Self::ChannelTableFull => formatter.write_str("the channel table is full"),
            Self::NoOwner => formatter.write_str("no owner is set"),
            Self::Busy => formatter.write_str("the core is busy"),
            Self::Stopped => formatter.write_str("the core has stopped"),
            Self::NotRunning => formatter.write_str("no identity is running"),
            Self::StartFailed { reason } => write!(formatter, "start failed: {reason:?}"),
            Self::Vault { error } => write!(formatter, "the vault failed: {error:?}"),
            Self::CountersNotRemoved => {
                formatter.write_str("the counter reservations were not removed")
            }
            Self::NoRadio => formatter.write_str("no radio is attached"),
            Self::NotThisPhone => formatter.write_str("the radio is not this phone's"),
            Self::NoAnswer => formatter.write_str("nothing answered"),
            Self::Unreachable => formatter.write_str("the device could not be reached"),
            Self::Unreadable => formatter.write_str("the answer could not be read"),
            Self::Cancelled => formatter.write_str("cancelled"),
            Self::SendFailed => formatter.write_str("the session could not send"),
            Self::DfuUnsupported => formatter.write_str("firmware update is unsupported"),
            Self::DfuRefused { status } => {
                write!(formatter, "firmware update refused with status {status}")
            }
            Self::DfuUnconfirmed => formatter.write_str("firmware update was not confirmed"),
            Self::EmergencyNotCertified => {
                formatter.write_str("the EMERGENCY warning has not been agreed to")
            }
            Self::MessageNotQueued { recorded } => {
                write!(
                    formatter,
                    "the message was kept but not queued (recorded: {recorded})"
                )
            }
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

impl From<SecretVaultError> for MobileAppError {
    fn from(error: SecretVaultError) -> Self {
        Self::Vault { error }
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

/// What queries read besides the store.
#[derive(Clone, Debug)]
struct Snapshot {
    lifecycle: MobileAppLifecycle,
    /// Whose rows the queries read.
    owner: Option<String>,
    /// The attached radio's address, while it carries this phone as its
    /// host.
    attached_host: Option<String>,
    /// The attached radio's state, while one is attached.
    radio: Option<MobileRadioStateRecord>,
    forward_secret_conversations: Vec<String>,
    meet: Option<crate::MobileMeetStateRecord>,
    revoking_claimed_radios: bool,
    /// The user agreed to `EMERGENCY`'s warning under `owner`.
    emergency_certified: bool,
    /// When, on the monotonic clock, an unnarrowed ask for identities may
    /// go again; `None` before the first.
    discovery_ready_at_ms: Option<i64>,
}

impl Snapshot {
    /// Read for `owner` from now on. A certification belongs to the owner
    /// it was given under, so another owner clears it; reports the flag
    /// when that changed it.
    fn change_owner(&mut self, owner: Option<String>) -> Option<bool> {
        let cleared = self.owner != owner && self.emergency_certified;
        self.owner = owner;
        if cleared {
            self.emergency_certified = false;
            return Some(false);
        }
        None
    }
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

/// What a session error means to a caller of the core. `UnknownConversation`
/// is left to the caller: the session also answers it for a channel whose
/// key it does not hold.
pub(super) fn mesh_error(error: MobileMeshError) -> MobileAppError {
    match error {
        MobileMeshError::SessionUnavailable => MobileAppError::NotRunning,
        MobileMeshError::NoAnswer => MobileAppError::NoAnswer,
        MobileMeshError::ChannelCapacity => MobileAppError::ChannelTableFull,
        MobileMeshError::InvalidPeer
        | MobileMeshError::InvalidRequest
        | MobileMeshError::InvalidRoute
        | MobileMeshError::InvalidLocation => MobileAppError::InvalidRequest,
        _ => MobileAppError::SendFailed,
    }
}

/// The application core.
#[derive(uniffi::Object)]
pub struct MobileAppCore {
    store: Arc<MobileAppStore>,
    clock: Arc<dyn Clock>,
    shared: Arc<Shared>,
    /// Dropping the object closes this, which takes the identity down and
    /// ends the worker as `stop` does, without waiting for it.
    jobs: mpsc::UnboundedSender<Job>,
    /// Becomes true when the worker has ended.
    finished: watch::Receiver<bool>,
}

#[uniffi::export]
impl MobileAppCore {
    /// A core over `store`, which native code opened and keeps using: both
    /// share its one connection. `vault` holds channel keys.
    #[uniffi::constructor]
    pub fn new(
        store: Arc<MobileAppStore>,
        vault: Arc<dyn SecretVault>,
        config: MobileAppConfigRecord,
    ) -> Result<Arc<Self>, MobileAppError> {
        Self::with_parts(
            store,
            vault,
            config,
            Arc::new(SystemClock),
            Options::default(),
        )
    }

    /// Replaces any listener set before.
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
    /// stopped; `start` sets it and `erase` clears it. Raises every list's
    /// change flag, since each now reads differently.
    pub fn set_owner(&self, owner_identity_id: Option<String>) -> Result<(), MobileAppError> {
        let mut refused = None;
        self.shared.publish(|snapshot| {
            if snapshot.lifecycle == MobileAppLifecycle::Stopped {
                refused = Some(MobileAppError::Stopped);
                return MobileAppChangesRecord::default();
            }
            MobileAppChangesRecord {
                emergency_certified: snapshot.change_owner(owner_identity_id),
                ..MobileAppChangesRecord::every_list()
            }
        });
        refused.map_or(Ok(()), Err)
    }

    pub fn status(&self) -> Result<MobileAppStatusRecord, MobileAppError> {
        let snapshot = self.shared.snapshot();
        match snapshot.lifecycle {
            MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
            lifecycle => Ok(MobileAppStatusRecord {
                lifecycle,
                radio: snapshot.radio.clone(),
                forward_secret_conversations: snapshot.forward_secret_conversations.clone(),
                meet: snapshot.meet.clone(),
                revoking_claimed_radios: snapshot.revoking_claimed_radios,
                emergency_certified: snapshot.emergency_certified,
            }),
        }
    }

    /// Bring `identity` up: the host key to the radio, the mesh session,
    /// the store's repairs, channels and chat, held paths, and the
    /// settings; then the radio's traffic. Resolves once running, or once
    /// failed. Running is reported with the channels, the conversations
    /// and every transcript changed, for what the start wrote. The session
    /// takes the secret out of `identity`, so a failed start needs a fresh
    /// unlock.
    pub async fn start(&self, identity: Arc<MobileIdentity>) -> Result<(), MobileAppError> {
        self.on_worker(move |worker| async move { worker.start(identity).await })
            .await
    }

    /// Take the identity down: the radio stops carrying it, the session
    /// shuts down, the channel keys and counter reservations go, and with
    /// `also_content` the store's content too. Native code erases the
    /// identity's secret first, and stops if that fails. Leaves the core
    /// idle, even when a later part fails. A start under way is waited
    /// out.
    pub async fn erase(&self, also_content: bool) -> Result<(), MobileAppError> {
        self.on_worker(move |worker| async move { worker.erase(also_content).await })
            .await
    }

    /// Finish the core. It resolves once the worker has ended; a second
    /// call waits for the same end, and a call on a stopped core does
    /// nothing.
    pub async fn stop(&self) {
        let job: Job = Box::new(|worker: Rc<Worker>| Box::pin(async move { worker.stop().await }));
        // A worker already gone has published its end.
        let _ = self.jobs.send(job);
        let mut finished = self.finished.clone();
        // The worker's sender goes with it, which ends the wait too.
        let _ = finished.wait_for(|finished| *finished).await;
    }

    /// Carry the mesh over `driver`, or over none. The core then takes the
    /// driver's updates and sets its host key and session; the previous
    /// driver is withdrawn from, not released. Native code calls this
    /// before dropping a driver's owner, never on a link loss.
    pub async fn use_radio(
        &self,
        driver: Option<Arc<MobileRadioDriver>>,
    ) -> Result<(), MobileAppError> {
        self.on_worker(move |worker| async move { worker.use_radio(driver).await })
            .await
    }

    /// The user's preferences. Kept in every state but stopped, and acted
    /// on while running.
    pub async fn set_policy(&self, policy: MobileAppPolicyRecord) -> Result<(), MobileAppError> {
        self.on_worker(move |worker| async move {
            worker.set_policy(policy).await;
            Ok(())
        })
        .await
    }

    /// The latest location reading while sharing, or `None` when there is
    /// none.
    pub async fn set_location(
        &self,
        position: Option<MobilePositionRecord>,
    ) -> Result<(), MobileAppError> {
        self.on_worker(move |worker| async move {
            worker.set_location(position).await;
            Ok(())
        })
        .await
    }

    /// The app came to the foreground: check the schedules and retry what
    /// waits for a retry.
    pub fn resumed(&self) {
        let job: Job = Box::new(|worker: Rc<Worker>| {
            Box::pin(async move {
                worker.schedule_check.notify_waiters();
                worker.policy_triggered();
            })
        });
        let _ = self.jobs.send(job);
    }
}

/// What tests change about a core.
#[derive(Default)]
pub(crate) struct Options {
    /// Sessions run on virtual time.
    #[cfg(test)]
    pub(crate) virtual_time: bool,
    #[cfg(test)]
    pub(crate) hooks: Arc<worker::TestHooks>,
}

impl MobileAppCore {
    pub(crate) fn with_parts(
        store: Arc<MobileAppStore>,
        vault: Arc<dyn SecretVault>,
        config: MobileAppConfigRecord,
        clock: Arc<dyn Clock>,
        options: Options,
    ) -> Result<Arc<Self>, MobileAppError> {
        let shared = Arc::new(Shared {
            snapshot: Mutex::new(Snapshot {
                lifecycle: MobileAppLifecycle::Idle,
                owner: None,
                attached_host: None,
                radio: None,
                forward_secret_conversations: Vec::new(),
                meet: None,
                revoking_claimed_radios: false,
                emergency_certified: false,
                discovery_ready_at_ms: None,
            }),
            changes: Mutex::new(MobileAppChangesRecord::default()),
            wake: WakeSignal::new(),
        });
        let parts = WorkerParts {
            store: store.clone(),
            vault,
            clock: clock.clone(),
            shared: shared.clone(),
            config,
            signals: Arc::new(Signals::default()),
            #[cfg(test)]
            virtual_time: options.virtual_time,
            #[cfg(test)]
            hooks: options.hooks,
        };
        #[cfg(not(test))]
        let _ = options;
        let (jobs, job_rx) = mpsc::unbounded_channel();
        let (finished_tx, finished) = watch::channel(false);
        std::thread::Builder::new()
            .name("umsh-app-core".to_owned())
            .spawn(move || worker::run(parts, job_rx, &finished_tx))
            .map_err(|_| MobileAppError::Stopped)?;
        Ok(Arc::new(Self {
            store,
            clock,
            shared,
            jobs,
            finished,
        }))
    }

    /// Run `work` on the worker as its own task, and answer with its result.
    async fn on_worker<T, F, Fut>(&self, work: F) -> Result<T, MobileAppError>
    where
        T: Send + 'static,
        F: FnOnce(Rc<Worker>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, MobileAppError>> + 'static,
    {
        let (answer, result) = oneshot::channel();
        let job: Job = Box::new(move |worker| {
            Box::pin(async move {
                let _ = answer.send(work(worker).await);
            })
        });
        self.jobs.send(job).map_err(|_| MobileAppError::Stopped)?;
        result.await.map_err(|_| MobileAppError::Stopped)?
    }

    /// The owner to read for, when the lifecycle allows a query.
    fn reader(&self) -> Result<String, MobileAppError> {
        let snapshot = self.shared.snapshot();
        match snapshot.lifecycle {
            MobileAppLifecycle::Erasing | MobileAppLifecycle::Stopping => Err(MobileAppError::Busy),
            MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
            MobileAppLifecycle::Idle
            | MobileAppLifecycle::Starting
            | MobileAppLifecycle::Running
            | MobileAppLifecycle::Failed { .. } => {
                snapshot.owner.clone().ok_or(MobileAppError::NoOwner)
            }
        }
    }
}
