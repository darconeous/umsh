//! Managing a device: the managed-device engine both apps share, which
//! holds a device's card, readings and queue over whichever link reaches
//! it.

use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{mpsc, oneshot};

mod carrier;
mod draft;
mod engine;
mod keys;
mod operation;
mod reading;
mod records;
mod refusal;
mod setup;
#[cfg(test)]
mod tests;
mod wifi;

pub use draft::{
    draft_add_meshcore_region, draft_add_repeater_region, draft_adopt_preset, draft_adopt_regions,
    draft_clear_position, draft_place, draft_place_from_phone, draft_set_precision,
};
pub(in crate::app_core) use engine::{Registry, Retired};
pub use records::{
    MobileAnnouncementReach, MobileApplyOutcome, MobileApplyResult, MobileApplyWarning,
    MobileBluetoothDraft, MobileBridgeDraft, MobileCategoryReadingRecord, MobileChoiceField,
    MobileChoiceList, MobileDraftDetails, MobileDraftKind, MobileDraftReviewRecord,
    MobileFieldProblem, MobileFieldProblemRecord, MobileGnssDraft, MobileHeardNetworkRecord,
    MobileIdentityDraft, MobileIntegerField, MobileKeyEntryRecord, MobileKeyTable,
    MobileKeyTableRecord, MobileManagedDeviceRecord, MobileManagementDraft, MobileManagementLink,
    MobileManagementOutcome, MobileManagementProblem, MobileMeshCoreDraft, MobileNetworkDraft,
    MobileOfferedCategoryRecord, MobileOptionalIntegerField, MobilePositionField,
    MobilePropertyRefusalRecord, MobilePropertyState, MobilePropertyStateRecord,
    MobilePropertyValueRecord, MobileRadioDraft, MobileRefusal, MobileRefusalReason,
    MobileRegionEntryProblem, MobileRepeaterDraft, MobileTemperatureNames,
    MobileTemperatureRowRecord, MobileTemperatureSummaryRecord, MobileTemperatureValue,
    MobileTextField, MobileTextListField, MobileTimeDraft, MobileToggleField, MobileWifiDraft,
    MobileWifiEntryCheckRecord, MobileWifiEntryProblem, MobileWifiJoinPlanRecord,
    MobileWifiOutcome, MobileWifiRefusal, MobileWifiStep,
};
pub use setup::{
    MobileDeviceSetup, MobileDeviceSetupRecord, MobileKeyListField, MobileSetupApplyOutcome,
    MobileSetupChoicesRecord, MobileSetupCompanionRecord, MobileSetupDraft, MobileSetupGoal,
    MobileSetupNote, MobileSetupProfile, MobileSetupProfileGap, MobileSetupRadioParameter,
    MobileSetupRefusal, MobileSetupResult, MobileSetupReviewRecord, MobileSetupSection,
    MobileSetupSetting, MobileSetupUnreadable, setup_adopt_preset, setup_set_radio_parameter,
};
pub use wifi::{wifi_edit_plan, wifi_entry_check, wifi_join_plan, wifi_offered_modes};

use carrier::Carrier;
use engine::{Ended, Engine, EngineKey, Published, next_id};

use super::routes::checked_address;
use super::worker::{Job, Worker};
use super::{MobileAppCore, MobileAppError, MobileAppLifecycle};
use crate::radio_driver::MobileRadioDriver;
use crate::ulcp::{
    MobileAnnouncementKind, UlcpAlertState, UlcpDfuMode, UlcpManageCategory, UlcpPropertyPushRecord,
};

/// The worker's job queue, as a handle holds it.
type Jobs = mpsc::WeakUnboundedSender<Job>;

/// One handle on a device being managed: its card, its readings, and what
/// this phone has asked of it. Made by `MobileAppCore`, run on the core's
/// worker. Every handle on one device shares one engine: one queue, one
/// set of readings, one snapshot.
///
/// A call whose future is dropped still runs to its end, which keeps a
/// write whole; only `cancel` and `release` cancel.
#[derive(uniffi::Object)]
pub struct MobileManagedDevice {
    /// The engine's id; equal for every handle on one engine.
    id: u64,
    /// This handle's own id.
    handle: u64,
    /// Weak, so a handle never keeps a dropped core's worker alive. Each
    /// call upgrades it; a failed upgrade answers `Stopped`.
    jobs: Jobs,
    published: Arc<Published>,
    closed: AtomicBool,
}

#[uniffi::export]
impl MobileManagedDevice {
    /// The engine's id, as `MobileAppChangesRecord.managed_devices` names
    /// it.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Everything a screen shows, as last published. Never waits on the
    /// worker.
    pub fn snapshot(&self) -> MobileManagedDeviceRecord {
        self.published.record()
    }

    /// Fill the card in from the cache, and ask the device when there is
    /// none, or off the mesh when it has not been read this lifetime.
    pub async fn load_card(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.load_card(&worker).await })
            .await
    }

    /// Ask the device what it is.
    pub async fn refresh_card(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.refresh_card(&worker).await })
            .await
    }

    /// Fill a category in from the cache, and off the mesh read it when
    /// it has not been read this lifetime.
    pub async fn load_category(
        &self,
        category: UlcpManageCategory,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine.load_category(&worker, category).await
        })
        .await
    }

    /// Ask the device for one category.
    pub async fn refresh_category(
        &self,
        category: UlcpManageCategory,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine.refresh_category(&worker, category).await
        })
        .await
    }

    /// A draft of `kind` built from the device's reading, or `None` while
    /// there is no reading, the device does not offer its category, or
    /// this handle is released.
    pub fn draft(&self, kind: MobileDraftKind) -> Option<MobileManagementDraft> {
        if self.closed.load(Ordering::SeqCst) {
            return None;
        }
        draft::build(&self.published.record(), kind)
    }

    /// `draft` on the device's current reading: fields the operator left
    /// alone follow the device, edits stand. The same variant comes back;
    /// `InvalidRequest` for one whose category the device does not offer.
    pub fn rebase(
        &self,
        draft: MobileManagementDraft,
    ) -> Result<MobileManagementDraft, MobileAppError> {
        self.open()?;
        draft::rebase(&self.published.record(), draft)
    }

    /// What Apply would write now, what it cannot, what to confirm first,
    /// and what the editor shows beside its fields. Rebases first, so a
    /// stale draft is judged on the current reading.
    pub fn review(
        &self,
        draft: MobileManagementDraft,
    ) -> Result<MobileDraftReviewRecord, MobileAppError> {
        self.open()?;
        draft::review(&self.published.record(), draft)
    }

    /// Write what `draft` changes, then save. Judged as `review` judges it,
    /// when called: a field problem writes nothing (`Invalid`), and a draft
    /// with no edits sends nothing (`NothingToApply`). `answered` says to
    /// rebuild the draft from the reading: the device answered the write,
    /// or there was nothing to write.
    pub async fn apply(
        &self,
        draft: MobileManagementDraft,
    ) -> Result<MobileApplyOutcome, MobileAppError> {
        self.open()?;
        draft::refuse_unoffered(&self.published.record(), &draft)?;
        self.on_engine(
            move |worker, engine| async move { engine.apply_draft(&worker, draft).await },
        )
        .await
    }

    /// Bring one of the device's key tables to `desired`: what `desired`
    /// changes in the table as it reads now is made to the table as it
    /// reads when the command's turn comes, so edits queued behind one
    /// another all take. This phone's own administrator entry and the last
    /// administrator are never taken out (`Failed { InvalidRequest }`,
    /// nothing sent).
    pub async fn set_keys(
        &self,
        table: MobileKeyTable,
        desired: Vec<Vec<u8>>,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine.set_keys(&worker, table, desired).await
        })
        .await
    }

    /// Ask the device to look for networks; `heard_networks` fills as it
    /// hears them. Across the mesh this returns once the scan ended, or is
    /// no longer followed: a second scan, a cancel or a release ends it.
    pub async fn scan_networks(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.scan_networks(&worker).await })
            .await
    }

    /// Store a network, turn the station on, join the network and save.
    /// `offered` is what a scan heard the network offer, which names the
    /// next mode to try when the device cannot use `security`. Neither the
    /// credential nor anything built from it is logged.
    pub async fn join_network(
        &self,
        ssid: Vec<u8>,
        security: u8,
        hidden: bool,
        credential: Vec<u8>,
        offered: Option<u16>,
    ) -> Result<MobileWifiOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine
                .join_network(&worker, ssid, security, hidden, credential, offered)
                .await
        })
        .await
    }

    /// Replace a network the device knows, and save. An empty credential
    /// under the stored mode keeps the stored one.
    pub async fn update_network(
        &self,
        ssid: Vec<u8>,
        security: u8,
        hidden: bool,
        auto_join: bool,
        credential: Vec<u8>,
    ) -> Result<MobileWifiOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine
                .update_network(&worker, ssid, security, hidden, auto_join, credential)
                .await
        })
        .await
    }

    /// Join a network the device knows, now.
    pub async fn join_known_network(
        &self,
        ssid: Vec<u8>,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine.join_known_network(&worker, ssid).await
        })
        .await
    }

    /// Leave the current network.
    pub async fn disconnect_network(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.disconnect_network(&worker).await })
            .await
    }

    /// Let the device join a network it knows by itself, or not, and save.
    pub async fn set_auto_join(
        &self,
        ssid: Vec<u8>,
        auto_join: bool,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine.set_auto_join(&worker, ssid, auto_join).await
        })
        .await
    }

    /// Forget a network, and save.
    pub async fn forget_network(
        &self,
        ssid: Vec<u8>,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(
            move |worker, engine| async move { engine.forget_network(&worker, ssid).await },
        )
        .await
    }

    /// Forget every host paired with the device.
    pub async fn clear_bluetooth_pairings(
        &self,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(
            |worker, engine| async move { engine.clear_bluetooth_pairings(&worker).await },
        )
        .await
    }

    /// Set the device's clock to now, unsaved.
    pub async fn set_clock_now(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.set_clock_now(&worker).await })
            .await
    }

    /// Zero the traffic counters the device answered for, unsaved, then
    /// read them again.
    pub async fn reset_counters(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.reset_counters(&worker).await })
            .await
    }

    /// Make the device conspicuous, or stop.
    pub async fn set_alert(
        &self,
        state: UlcpAlertState,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move { engine.set_alert(&worker, state).await })
            .await
    }

    /// Put the device into firmware update. Once it confirms, nothing
    /// more is asked of it.
    pub async fn enter_dfu(
        &self,
        mode: UlcpDfuMode,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move { engine.enter_dfu(&worker, mode).await })
            .await
    }

    /// Restart the device, keeping what it saved.
    pub async fn restart(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.restart(&worker).await })
            .await
    }

    /// Ask the device to announce itself now.
    pub async fn announce(
        &self,
        kind: MobileAnnouncementKind,
        reach: MobileAnnouncementReach,
    ) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(
            move |worker, engine| async move { engine.announce(&worker, kind, reach).await },
        )
        .await
    }

    /// Return the device to a blank factory state. Offered off the mesh
    /// only; the device's cache goes whatever the outcome.
    pub async fn factory_reset(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move { engine.factory_reset(&worker).await })
            .await
    }

    /// The operator's Cancel: everything queued or running on this
    /// device, reads and writes, whichever handle asked. A request on
    /// the air may still be acted on.
    pub fn cancel(&self) {
        self.published.cancel();
    }

    /// This handle is done. When it is the last open one on its device,
    /// the device is relinquished: reads are canceled and refused, writes
    /// run to their end, and it is forgotten once nothing is queued.
    /// Idempotent; dropping a handle does the same, later. Not `close`:
    /// Kotlin's generated objects already have a `close()`, which frees
    /// the handle and so releases it too.
    pub fn release(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let (id, handle) = (self.id, self.handle);
        self.send(move |worker| {
            let engine = worker.managed.borrow().engine(id);
            if let Some(engine) = engine {
                engine.close_handle(&worker, handle);
            }
        });
    }

    /// What a driver native code drains (the administrative one) pushed,
    /// with how many pushes it let go of: any lost reads every category
    /// held again. The companion's arrive without this.
    pub fn receive_pushes(&self, pushes: Vec<UlcpPropertyPushRecord>, dropped: u64) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let id = self.id;
        self.send(move |worker| {
            let engine = worker.managed.borrow().engine(id);
            if let Some(engine) = engine
                && engine.current(worker.owner().as_ref())
            {
                engine.absorb_pushes(&worker, &pushes);
                if dropped > 0 {
                    engine.resync(&worker);
                }
            }
        });
    }

    /// Clear the problem the status bar shows.
    pub fn dismiss_problem(&self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let id = self.id;
        self.send(move |worker| {
            let engine = worker.managed.borrow().engine(id);
            if let Some(engine) = engine {
                engine.dismiss_problem(&worker);
            }
        });
    }
}

#[cfg(test)]
impl MobileManagedDevice {
    /// Forget everything cached about the device, so the next open asks
    /// it afresh. A factory reset does this on its own.
    pub async fn forget_cache(&self) -> Result<MobileManagementOutcome, MobileAppError> {
        self.on_engine(|worker, engine| async move {
            engine.forget_cache(&worker);
            MobileManagementOutcome::Done
        })
        .await
    }

    /// Write `desired`'s `dirty` properties, fold the echoes, and with
    /// `save` keep them unless the device refused any: the apply
    /// pipeline's raw entry, with a dirty set the test computed. Editors
    /// apply drafts.
    pub async fn apply_properties(
        &self,
        category: UlcpManageCategory,
        desired: crate::ulcp::UlcpDevicePropertiesRecord,
        dirty: Vec<u32>,
        save: bool,
    ) -> Result<MobileApplyOutcome, MobileAppError> {
        self.on_engine(move |worker, engine| async move {
            engine
                .apply_properties(&worker, category, desired, dirty, save)
                .await
        })
        .await
    }
}

impl Drop for MobileManagedDevice {
    fn drop(&mut self) {
        self.release();
    }
}

impl MobileManagedDevice {
    /// `Stopped` once this handle is released.
    fn open(&self) -> Result<(), MobileAppError> {
        if self.closed.load(Ordering::SeqCst) {
            Err(MobileAppError::Stopped)
        } else {
            Ok(())
        }
    }

    fn new(jobs: Jobs, engine: &Rc<Engine>) -> Self {
        let handle = next_id();
        engine.open_handle(handle);
        Self {
            id: engine.id,
            handle,
            jobs,
            published: engine.published.clone(),
            closed: AtomicBool::new(false),
        }
    }

    /// Run `work` on the worker without an answer, when the core still
    /// lives.
    fn send(&self, work: impl FnOnce(Rc<Worker>) + Send + 'static) {
        let Some(jobs) = self.jobs.upgrade() else {
            return;
        };
        let job: Job = Box::new(move |worker| {
            Box::pin(async move {
                work(worker);
            })
        });
        let _ = jobs.send(job);
    }

    /// Run `work` against this handle's engine on the worker, in every
    /// lifecycle that takes commands.
    async fn on_engine<T, F, Fut>(&self, work: F) -> Result<T, MobileAppError>
    where
        T: Ended + Send + 'static,
        F: FnOnce(Rc<Worker>, Rc<Engine>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
    {
        if self.closed.load(Ordering::SeqCst) {
            return Err(MobileAppError::Stopped);
        }
        let jobs = self.jobs.upgrade().ok_or(MobileAppError::Stopped)?;
        let id = self.id;
        let (answer, result) = oneshot::channel();
        let job: Job = Box::new(move |worker: Rc<Worker>| {
            Box::pin(async move {
                let _ = answer.send(on_engine(worker, id, work).await);
            })
        });
        jobs.send(job).map_err(|_| MobileAppError::Stopped)?;
        drop(jobs);
        result.await.map_err(|_| MobileAppError::Stopped)?
    }
}

async fn on_engine<T, F, Fut>(worker: Rc<Worker>, id: u64, work: F) -> Result<T, MobileAppError>
where
    T: Ended,
    F: FnOnce(Rc<Worker>, Rc<Engine>) -> Fut,
    Fut: Future<Output = T>,
{
    admitted(&worker)?;
    let engine = worker
        .managed
        .borrow()
        .engine(id)
        .ok_or(MobileAppError::Stopped)?;
    if let Some(refusal) = engine.refusal(&worker) {
        return refusal;
    }
    let outcome = work(worker, engine.clone()).await;
    engine.ended(outcome)
}

/// Whether the lifecycle takes management: every state but erasing and
/// stopping (`Busy`) and stopped.
fn admitted(worker: &Worker) -> Result<(), MobileAppError> {
    match worker.lifecycle() {
        MobileAppLifecycle::Erasing | MobileAppLifecycle::Stopping => Err(MobileAppError::Busy),
        MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
        MobileAppLifecycle::Idle
        | MobileAppLifecycle::Starting
        | MobileAppLifecycle::Running
        | MobileAppLifecycle::Failed { .. } => Ok(()),
    }
}

/// The canonical address of a checked one.
fn canonical(address: &str) -> Result<(Vec<u8>, String), MobileAppError> {
    let key = crate::public_identity_bytes(address.to_owned())?;
    let canonical = crate::inspect_public_identity_bytes(key.clone())?.canonical_address;
    Ok((key, canonical))
}

impl Worker {
    /// The engine registered under `key` for the current owner, or a new
    /// one `make` builds, with a new handle on it.
    fn managed_device(
        &self,
        key: EngineKey,
        jobs: Jobs,
        make: impl FnOnce(Option<String>) -> Rc<Engine>,
    ) -> MobileManagedDevice {
        let owner = self.owner();
        let existing = self.managed.borrow().live(&key, owner.as_ref());
        let engine = existing.unwrap_or_else(|| {
            let engine = make(owner);
            self.managed.borrow_mut().insert(engine.clone());
            engine
        });
        MobileManagedDevice::new(jobs, &engine)
    }

    /// The companion device over the core's radio.
    fn manage_companion(
        &self,
        driver: Arc<MobileRadioDriver>,
        uses_bluetooth: bool,
        jobs: Jobs,
    ) -> MobileManagedDevice {
        let key = EngineKey::Companion(Arc::as_ptr(&driver) as usize);
        self.managed_device(key, jobs, |owner| {
            Engine::new(
                EngineKey::Companion(Arc::as_ptr(&driver) as usize),
                MobileManagementLink::Companion,
                uses_bluetooth,
                Carrier::Companion { driver },
                owner,
                None,
            )
        })
    }

    /// A device native code administers over `driver`: storeless, and
    /// shared by every handle on that driver, whose first caller's key and
    /// transport stand.
    fn manage_administered_device(
        &self,
        driver: Arc<MobileRadioDriver>,
        phone_node_key: Option<Vec<u8>>,
        uses_bluetooth: bool,
        jobs: Jobs,
    ) -> MobileManagedDevice {
        let key = EngineKey::Administrative(Arc::as_ptr(&driver) as usize);
        self.managed_device(key.clone(), jobs, |_| {
            Engine::new(
                key,
                MobileManagementLink::Administrative,
                uses_bluetooth,
                Carrier::Administrative {
                    driver,
                    phone_node_key,
                },
                None,
                None,
            )
        })
    }

    /// Hand what the core's radio pushed to every device managed over it
    /// that still takes commands; with any lost (`dropped`), each reads
    /// what it holds again. One retired, or made for another owner, but
    /// still held open keeps nothing.
    pub(in crate::app_core) fn managed_pushes(
        self: &Rc<Self>,
        driver: &Arc<MobileRadioDriver>,
        pushes: &[UlcpPropertyPushRecord],
        dropped: u64,
    ) {
        if pushes.is_empty() && dropped == 0 {
            return;
        }
        let owner = self.owner();
        let engines = self.managed.borrow().all();
        for engine in engines {
            if engine.current(owner.as_ref())
                && engine
                    .carrier
                    .driver()
                    .is_some_and(|bound| Arc::ptr_eq(bound, driver))
            {
                if !pushes.is_empty() {
                    engine.absorb_pushes(self, pushes);
                }
                if dropped > 0 {
                    engine.resync(self);
                }
            }
        }
    }

    /// Close every managed device: what is queued ends, and nothing more
    /// is taken.
    pub(in crate::app_core) fn retire_managed(&self, retired: Retired) {
        let engines = self.managed.borrow().all();
        for engine in engines {
            engine.retire(self, retired);
        }
    }
}

#[uniffi::export]
impl MobileAppCore {
    /// Manage the device at `address`: over the attached radio's own link
    /// when `address` is that radio's device identity, else across the
    /// mesh, which needs an owner. `uses_bluetooth` is the transport's,
    /// which the core does not know; a mesh device ignores it.
    pub async fn manage_device(
        &self,
        address: String,
        uses_bluetooth: bool,
    ) -> Result<Arc<MobileManagedDevice>, MobileAppError> {
        checked_address(&address)?;
        let (key, address) = canonical(&address)?;
        let jobs = self.jobs.downgrade();
        self.on_worker(move |worker| async move {
            admitted(&worker)?;
            if let Some(driver) = worker.driver()
                && driver.state().device_key.as_ref() == Some(&key)
            {
                return Ok(Arc::new(worker.manage_companion(
                    driver,
                    uses_bluetooth,
                    jobs,
                )));
            }
            if worker.owner().is_none() {
                return Err(MobileAppError::NoOwner);
            }
            let device = worker.managed_device(EngineKey::Mesh(address.clone()), jobs, |owner| {
                Engine::new(
                    EngineKey::Mesh(address.clone()),
                    MobileManagementLink::Mesh,
                    false,
                    Carrier::Mesh {
                        address: address.clone(),
                    },
                    owner,
                    Some(address),
                )
            });
            Ok(Arc::new(device))
        })
        .await
    }

    /// Manage the device `driver` is attached to: an administrative driver
    /// native code owns, drains and stops. Nothing is cached.
    /// `phone_node_key` is what native code knows this phone's key to be
    /// on that device. Native code forwards the driver's pushes with
    /// `receive_pushes`, and tears its session down once the device
    /// enters firmware update. A later call for the same driver returns
    /// the same device: the first call's `phone_node_key` and
    /// `uses_bluetooth` stand while any handle holds it.
    pub async fn manage_administered(
        &self,
        driver: Arc<MobileRadioDriver>,
        phone_node_key: Option<Vec<u8>>,
        uses_bluetooth: bool,
    ) -> Result<Arc<MobileManagedDevice>, MobileAppError> {
        let jobs = self.jobs.downgrade();
        self.on_worker(move |worker| async move {
            admitted(&worker)?;
            Ok(Arc::new(worker.manage_administered_device(
                driver,
                phone_node_key,
                uses_bluetooth,
                jobs,
            )))
        })
        .await
    }

    /// Manage the attached radio over its own link. Nothing is cached
    /// when the radio holds no device identity or no owner is set.
    pub async fn manage_radio(
        &self,
        uses_bluetooth: bool,
    ) -> Result<Arc<MobileManagedDevice>, MobileAppError> {
        let jobs = self.jobs.downgrade();
        self.on_worker(move |worker| async move {
            admitted(&worker)?;
            let driver = worker.driver().ok_or(MobileAppError::NoRadio)?;
            Ok(Arc::new(worker.manage_companion(
                driver,
                uses_bluetooth,
                jobs,
            )))
        })
        .await
    }
}

impl MobileAppCore {
    /// A device the engine's tests script, built as the public
    /// constructors build theirs.
    #[cfg(test)]
    pub(in crate::app_core::manage) async fn manage_scripted(
        &self,
        script: Arc<carrier::ScriptedCarrier>,
        link: MobileManagementLink,
    ) -> Result<Arc<MobileManagedDevice>, MobileAppError> {
        let jobs = self.jobs.downgrade();
        self.on_worker(move |worker| async move {
            admitted(&worker)?;
            let key = EngineKey::Scripted(Arc::as_ptr(&script) as usize);
            let address = script.address.clone();
            let device = worker.managed_device(key.clone(), jobs, |owner| {
                Engine::new(key, link, false, Carrier::Scripted(script), owner, address)
            });
            Ok(Arc::new(device))
        })
        .await
    }
}
