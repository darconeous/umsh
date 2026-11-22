//! Setting up a device in hand as a tracker or a repeater: the goals'
//! rules, the draft the sheet edits, what Apply would write, how a
//! read-back is checked, and the object that runs it on the device's
//! administrative engine.

use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::oneshot;

mod apply;
mod draft;
mod plan;
mod records;
mod review;
mod verify;

pub use draft::{setup_adopt_preset, setup_set_radio_parameter};
pub use records::{
    MobileDeviceSetupRecord, MobileKeyListField, MobileSetupApplyOutcome, MobileSetupChoicesRecord,
    MobileSetupCompanionRecord, MobileSetupDraft, MobileSetupGoal, MobileSetupNote,
    MobileSetupProfile, MobileSetupProfileGap, MobileSetupRadioParameter, MobileSetupRefusal,
    MobileSetupResult, MobileSetupReviewRecord, MobileSetupSection, MobileSetupSetting,
    MobileSetupUnreadable,
};

#[cfg(test)]
pub(in crate::app_core::manage) use {
    draft::{
        DEFAULTS, Defaults, Gates, Setup, add_administrator, build, build_with, companion_record,
        remove_administrator, resolve_profile, set_phone_administers, unreadable,
    },
    plan::{Assumption, assumptions, notes, refusal, sections, sets_clock},
    review::{Standing, choices, default_region_unlisted, snapshot, unshown_setting},
    verify::{advertised_role, first_mismatch},
};

use self::apply::{Applied, Plan};
use self::draft::Setup as Built;
use self::review::Standing as Stands;
use super::keys::key_table_diff;
use super::{Jobs, MobileManagedDevice, admitted, on_engine};
use crate::app_core::worker::{Job, Worker};
use crate::app_core::{MobileAppCore, MobileAppError};
use crate::radio_driver::MobileRadioDriver;
use crate::time_zone::device_accepts;
use crate::ulcp::{UlcpDeviceConfigRecord, UlcpSyncRecord};

/// What a setup holds besides its engine. Written by the setup's methods
/// and, for an apply, inside the apply's own job.
struct SetupState {
    goal: MobileSetupGoal,
    /// The draft's rules, or why the goal cannot use the device.
    setup: Result<Built, MobileSetupRefusal>,
    /// The engine's key for this phone.
    phone_node_key: Option<Vec<u8>>,
    /// The draft as the goal built it, then as the last apply left it.
    draft: Option<MobileSetupDraft>,
    /// What the device reports now: the attach's record, then each
    /// read-back.
    reported: Option<UlcpSyncRecord>,
    /// The configuration the device last confirmed.
    applied: Option<UlcpDeviceConfigRecord>,
    last_result: Option<MobileSetupResult>,
    applying: bool,
    released: bool,
}

type Shared = Arc<Mutex<SetupState>>;

fn locked(state: &Shared) -> MutexGuard<'_, SetupState> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One device being set up: what it reported, what the goal decided, and
/// the write that tells it. Released with `release()` or on drop.
#[derive(uniffi::Object)]
pub struct MobileDeviceSetup {
    /// The administrative engine's id.
    engine: u64,
    /// Weak, so a setup never keeps a dropped core's worker alive.
    jobs: Jobs,
    /// The handle that keeps the engine registered, until released.
    device: Mutex<Option<MobileManagedDevice>>,
    state: Shared,
}

#[uniffi::export]
impl MobileDeviceSetup {
    /// Everything the sheet shows that is not the draft. Never waits.
    pub fn snapshot(&self) -> MobileDeviceSetupRecord {
        let state = locked(&self.state);
        review::snapshot(
            state.goal,
            state.setup.as_ref().map_err(|refusal| *refusal),
            state.phone_node_key.clone(),
            state.reported.clone(),
            state.applying,
            state.last_result.clone(),
        )
    }

    /// The draft to edit now, or `None` for a refused device: as the goal
    /// built it, then as the last apply left it (its outcome's draft).
    /// Native code keeps its own copy and edits it; this is for a screen
    /// rebuilt from the handle.
    pub fn draft(&self) -> Option<MobileSetupDraft> {
        locked(&self.state).draft.clone()
    }

    /// What Apply would do with `draft` now. `Stopped` once released;
    /// `InvalidRequest` for a device the goal refused, which has no draft.
    pub fn review(
        &self,
        draft: MobileSetupDraft,
    ) -> Result<MobileSetupReviewRecord, MobileAppError> {
        let state = locked(&self.state);
        if state.released {
            return Err(MobileAppError::Stopped);
        }
        let setup = state
            .setup
            .as_ref()
            .map_err(|_| MobileAppError::InvalidRequest)?;
        Ok(setup.review(&draft, standing(&state)))
    }

    /// Configure, read back, edit the administrators, set the clock, verify.
    /// `InvalidRequest` while another apply on this setup runs; `Invalid`
    /// (nothing sent) when review would not allow it. Once queued, an
    /// apply runs to its end whatever the caller does: its result reaches
    /// `snapshot()` and `draft()` even if this call's future is dropped.
    pub async fn apply(
        &self,
        draft: MobileSetupDraft,
    ) -> Result<MobileSetupApplyOutcome, MobileAppError> {
        let plan = {
            let mut state = locked(&self.state);
            if state.released {
                return Err(MobileAppError::Stopped);
            }
            if state.applying {
                return Err(MobileAppError::InvalidRequest);
            }
            let Ok(setup) = state.setup.as_ref() else {
                return Ok(invalid(draft));
            };
            if !setup.review(&draft, standing(&state)).can_apply {
                return Ok(invalid(draft));
            }
            let Some(plan) = plan_of(setup, &draft) else {
                return Ok(invalid(draft));
            };
            state.applying = true;
            state.applied = None;
            state.last_result = None;
            plan
        };
        // Whatever becomes of the job, the setup is not left applying.
        let guard = Applying(Some(self.state.clone()));
        let jobs = self.jobs.upgrade().ok_or(MobileAppError::Stopped)?;
        let engine = self.engine;
        let (answer, result) = oneshot::channel();
        let job: Job = Box::new(move |worker: Rc<Worker>| {
            Box::pin(async move {
                let mut guard = guard;
                // An engine retired before anything was sent answers the
                // retirement's error, as a stop in its queue would.
                let retired = worker
                    .managed
                    .borrow()
                    .engine(engine)
                    .and_then(|engine| engine.retirement());
                let applied = match retired {
                    Some(error) => Err(error),
                    None => {
                        on_engine(worker, engine, move |worker, engine| async move {
                            apply::apply(&worker, &engine, plan).await
                        })
                        .await
                    }
                };
                // Inside the job, so a caller that stopped waiting still
                // leaves the setup as the apply ended.
                let outcome = guard.finish(draft, applied);
                let _ = answer.send(outcome);
            })
        });
        jobs.send(job).map_err(|_| MobileAppError::Stopped)?;
        drop(jobs);
        result.await.map_err(|_| MobileAppError::Stopped)?
    }

    /// Put this phone on the administrator list or take it off. Unchanged
    /// when this phone's key is unknown, or when the list is full and the
    /// phone is not on it.
    pub fn set_phone_administers(
        &self,
        draft: MobileSetupDraft,
        administers: bool,
    ) -> MobileSetupDraft {
        let phone = locked(&self.state).phone_node_key.clone();
        draft::set_phone_administers(draft, phone.as_deref(), administers)
    }

    /// Let `key` manage the device. Idempotent; unchanged on a full list.
    pub fn add_administrator(&self, draft: MobileSetupDraft, key: Vec<u8>) -> MobileSetupDraft {
        draft::add_administrator(draft, &key)
    }

    /// Stop `key` managing the device. This phone's key and the last
    /// entry included.
    pub fn remove_administrator(&self, draft: MobileSetupDraft, key: Vec<u8>) -> MobileSetupDraft {
        draft::remove_administrator(draft, &key)
    }

    /// This setup is done; idempotent. Later `review` and `apply` answer
    /// `Stopped`. An apply under way runs to its end; the engine stays
    /// registered until its queue empties.
    pub fn release(&self) {
        locked(&self.state).released = true;
        let device = self
            .device
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(device) = device {
            device.release();
        }
    }
}

impl Drop for MobileDeviceSetup {
    fn drop(&mut self) {
        self.release();
    }
}

/// Where `state` stands, for review.
fn standing(state: &SetupState) -> Stands<'_> {
    Stands {
        applying: state.applying,
        released: state.released,
        applied: state.applied.as_ref(),
    }
}

/// An apply review would not allow: nothing sent, the draft as given.
fn invalid(draft: MobileSetupDraft) -> MobileSetupApplyOutcome {
    MobileSetupApplyOutcome {
        result: MobileSetupResult::Invalid,
        draft,
    }
}

/// What Apply does with `draft`, settled now; `None` for a draft the
/// encoder refuses, which review already reports.
fn plan_of(setup: &Built, draft: &MobileSetupDraft) -> Option<Plan> {
    let record = setup.record(draft)?;
    let writes = setup.writes(record.clone())?;
    let field = &draft.administrators;
    let asked = key_table_diff(&field.reported, &field.value);
    Some(Plan {
        record,
        writes,
        unreadable: setup.sync.unreadable_properties.clone(),
        administrators: (field.known && !asked.is_empty()).then_some(asked),
        reported_administrators: field.reported.clone(),
        sets_clock: plan::sets_clock(setup.goal, &setup.sync),
    })
}

/// Leave the setup as the apply ended, and the outcome to answer. The
/// draft to keep carries the transmit power the device reported (it
/// clamps one its radio cannot reach) and the administrator list the
/// edits left.
fn finish(
    state: &mut SetupState,
    draft: MobileSetupDraft,
    applied: Result<Applied, MobileAppError>,
) -> Result<MobileSetupApplyOutcome, MobileAppError> {
    state.applying = false;
    let applied = applied?;
    let mut draft = draft;
    if let Some(reported) = &applied.read_back {
        draft.radio.transmit_power_dbm.value = reported.transmit_power_dbm.into();
        state.reported = Some(reported.clone());
    }
    if let Some(after) = applied.administrators {
        draft.administrators.reported = after.clone();
        draft.administrators.value = after;
    }
    if matches!(applied.result, MobileSetupResult::Configured { .. }) {
        state.applied = state
            .setup
            .as_ref()
            .ok()
            .and_then(|setup| setup.record(&draft));
    }
    state.last_result = Some(applied.result.clone());
    state.draft = Some(draft.clone());
    Ok(MobileSetupApplyOutcome {
        result: applied.result,
        draft,
    })
}

/// An apply under way on a setup. Dropped without finishing (the worker
/// gone, or the job never run), it clears `applying`.
struct Applying(Option<Shared>);

impl Applying {
    fn finish(
        &mut self,
        draft: MobileSetupDraft,
        applied: Result<Applied, MobileAppError>,
    ) -> Result<MobileSetupApplyOutcome, MobileAppError> {
        let state = self.0.take().expect("an apply finishes once");
        finish(&mut locked(&state), draft, applied)
    }
}

impl Drop for Applying {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            locked(&state).applying = false;
        }
    }
}

impl Worker {
    /// A setup on the device `device` holds, as `goal`: built from what the
    /// device reported when it attached (`sync`) and the name its link
    /// knows it by.
    fn set_up(
        &self,
        device: MobileManagedDevice,
        sync: Option<UlcpSyncRecord>,
        name: Option<String>,
        goal: MobileSetupGoal,
        companion: Option<&MobileSetupCompanionRecord>,
        phone_zone_rule: &str,
    ) -> MobileDeviceSetup {
        // The engine's key, which the first caller on it set: the setup and
        // the management screens never disagree about which entry is this
        // phone.
        let phone_node_key = self
            .managed
            .borrow()
            .engine(device.id)
            .and_then(|engine| engine.carrier.phone_node_key(self));
        let setup = draft::build(
            goal,
            sync.as_ref(),
            name,
            companion,
            phone_node_key.clone(),
            phone_zone_rule,
        );
        let draft = setup.as_ref().ok().map(|setup| setup.built.clone());
        MobileDeviceSetup {
            engine: device.id,
            jobs: device.jobs.clone(),
            device: Mutex::new(Some(device)),
            state: Arc::new(Mutex::new(SetupState {
                goal,
                setup,
                phone_node_key,
                draft,
                reported: sync,
                applied: None,
                last_result: None,
                applying: false,
                released: false,
            })),
        }
    }
}

#[uniffi::export]
impl MobileAppCore {
    /// The radio profile a set-up device is put on: this phone's radio's
    /// name and PHY values as it reports them now, or `None` with no
    /// radio or no report. Called once when the setup sheet opens and
    /// handed to every `set_up_device` of that sheet, so a mesh profile
    /// that changes mid-session does not split the devices set up in it.
    pub async fn setup_companion(
        &self,
    ) -> Result<Option<MobileSetupCompanionRecord>, MobileAppError> {
        self.on_worker(|worker| async move {
            admitted(&worker)?;
            Ok(worker.driver().and_then(|driver| {
                let state = driver.state();
                let sync = state.provisioning?;
                Some(draft::companion_record(state.name, &sync))
            }))
        })
        .await
    }

    /// Set up the device `driver` is attached to as `goal`. `driver` is an
    /// administrative driver native code owns, attached with
    /// `lazy_inspection: false`; a lazily attached one is `InvalidRequest`.
    /// Answers even for a device the goal cannot use: the record's
    /// `refusal` says why, and `draft` is `None`.
    ///
    /// Shares the administrative engine `manage_administered` makes for the
    /// same driver: one queue, and the first call's `phone_node_key` and
    /// `uses_bluetooth` stand while any handle holds it; the record's
    /// `phone_node_key` is the engine's. `phone_zone_rule` is the phone's,
    /// from `phone_zone_rule`; a rule no device accepts is `InvalidRequest`.
    pub async fn set_up_device(
        &self,
        driver: Arc<MobileRadioDriver>,
        goal: MobileSetupGoal,
        companion: Option<MobileSetupCompanionRecord>,
        phone_node_key: Option<Vec<u8>>,
        uses_bluetooth: bool,
        phone_zone_rule: String,
    ) -> Result<Arc<MobileDeviceSetup>, MobileAppError> {
        // A lazy attach read only what a screen asked for: it is not the
        // whole configuration a setup writes back.
        if driver.lazy_inspection || !device_accepts(&phone_zone_rule) {
            return Err(MobileAppError::InvalidRequest);
        }
        let jobs = self.jobs.downgrade();
        self.on_worker(move |worker| async move {
            admitted(&worker)?;
            let state = driver.state();
            let device =
                worker.manage_administered_device(driver, phone_node_key, uses_bluetooth, jobs);
            Ok(Arc::new(worker.set_up(
                device,
                state.provisioning,
                state.name,
                goal,
                companion.as_ref(),
                &phone_zone_rule,
            )))
        })
        .await
    }
}

impl MobileAppCore {
    /// A setup on a device the engine's tests script, over the
    /// administrative link, built as `set_up_device` builds one. The
    /// script's own key for this phone stands for the engine's.
    #[cfg(test)]
    pub(in crate::app_core::manage) async fn set_up_scripted(
        &self,
        script: Arc<super::carrier::ScriptedCarrier>,
        goal: MobileSetupGoal,
        companion: Option<MobileSetupCompanionRecord>,
        phone_zone_rule: String,
    ) -> Result<Arc<MobileDeviceSetup>, MobileAppError> {
        use super::carrier::Carrier;
        use super::engine::{Engine, EngineKey};
        use super::records::MobileManagementLink;
        if !device_accepts(&phone_zone_rule) {
            return Err(MobileAppError::InvalidRequest);
        }
        let jobs = self.jobs.downgrade();
        self.on_worker(move |worker| async move {
            admitted(&worker)?;
            let sync = script.sync();
            let name = sync.as_ref().and_then(|sync| sync.device_name.clone());
            let key = EngineKey::Scripted(Arc::as_ptr(&script) as usize);
            let device = worker.managed_device(key.clone(), jobs, |_| {
                Engine::new(
                    key,
                    MobileManagementLink::Administrative,
                    false,
                    Carrier::Scripted(script),
                    None,
                    None,
                )
            });
            Ok(Arc::new(worker.set_up(
                device,
                sync,
                name,
                goal,
                companion.as_ref(),
                &phone_zone_rule,
            )))
        })
        .await
    }
}
