//! One engine per managed device, on the core's worker: its queue, its
//! card and readings, and the rules for reading and writing them.
//!
//! Every handle on one device shares its engine, so two screens on one
//! device keep one set of readings and one queue. State lives in
//! `RefCell`s never borrowed across an await; what handles read from any
//! thread (the published record and the queue's operations, for a cancel)
//! lives behind leaf locks in [`Published`].

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;
use umsh_ulcp::ids::prop;

use super::carrier::Carrier;
use super::draft;
use super::keys::{apply_key_table, key_table_diff};
use super::operation::Operation;
use super::reading::{Failure, Reading, persistent};
use super::records::MobileManagementDraft;
use super::records::{
    MobileAnnouncementReach, MobileApplyOutcome, MobileApplyResult, MobileHeardNetworkRecord,
    MobileKeyEntryRecord, MobileKeyTable, MobileKeyTableRecord, MobileManagedDeviceRecord,
    MobileManagementLink, MobileManagementOutcome, MobileManagementProblem as Problem,
    MobileOfferedCategoryRecord, MobileRefusal, MobileWifiOutcome, MobileWifiRefusal,
    MobileWifiStep,
};
use super::refusal::{Stop, classify};
use super::wifi::{classify_join, classify_update};
use crate::app_core::MobileAppError;
use crate::app_core::records::MobileAppChangesRecord;
use crate::app_core::worker::Worker;
use crate::mobile_mesh::{
    MobileMeshManagementAnswerRecord, MobileMeshPropertyWriteRecord, MobileMeshResetScope,
};
use crate::store::MobileStoredManagementCardRecord;
use crate::ulcp::{
    MobileAnnouncementKind, MobileAnnouncementRecord, UlcpAlertState, UlcpDeviceCardRecord,
    UlcpDevicePropertiesRecord, UlcpDfuMode, UlcpManageCategory, UlcpPropertyPushKind,
    UlcpPropertyPushRecord, UlcpTimeRecord, UlcpWifiScanResultRecord, inspect_ulcp_alert,
    inspect_ulcp_device_card, inspect_ulcp_properties, inspect_ulcp_wifi_scan_result,
    ulcp_card_properties, ulcp_category_properties, ulcp_dirty_writes, ulcp_property_record,
    ulcp_wifi_network_item,
};

/// Engine, handle and queue-entry ids, unique for the process.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// How a mesh scan is followed: the flag read every two seconds, at most
/// twenty times, longer than any scan runs.
const SCAN_POLL_STEP_MS: i64 = 2_000;
const SCAN_POLL_ROUNDS: usize = 20;

/// Flood hops of an announcement's reach.
const NEARBY_HOPS: u8 = 0;
const MESH_HOPS: u8 = 5;

/// The order the categories are suggested in.
const CATEGORY_ORDER: [UlcpManageCategory; 13] = [
    UlcpManageCategory::Power,
    UlcpManageCategory::Sensors,
    UlcpManageCategory::Radio,
    UlcpManageCategory::Statistics,
    UlcpManageCategory::Identity,
    UlcpManageCategory::Gnss,
    UlcpManageCategory::Time,
    UlcpManageCategory::Bluetooth,
    UlcpManageCategory::Wifi,
    UlcpManageCategory::Network,
    UlcpManageCategory::Bridge,
    UlcpManageCategory::Repeater,
    UlcpManageCategory::PeerNodes,
];

/// What a read asks for, so an automatic one is not asked twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Read {
    Card,
    Category(UlcpManageCategory),
}

/// One thing asked of the device, waiting its turn or running.
pub(super) struct Entry {
    id: u64,
    /// It changes the device, as opposed to only asking it.
    changes_device: bool,
    read: Option<Read>,
    operation: Arc<Operation>,
}

/// What an engine's handles read on any thread.
pub(super) struct Published {
    record: Mutex<MobileManagedDeviceRecord>,
    queue: Mutex<VecDeque<Entry>>,
    /// What stops the mesh scan poll, while one runs. Not a queue entry:
    /// between its reads nothing is queued.
    poll: Mutex<Option<Arc<Operation>>>,
}

impl Published {
    pub(super) fn record(&self) -> MobileManagedDeviceRecord {
        self.record
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn queue(&self) -> MutexGuard<'_, VecDeque<Entry>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The operator's Cancel: everything queued or running, reads and
    /// writes, and a scan being followed.
    pub(super) fn cancel(&self) {
        for entry in self.queue().iter() {
            entry.operation.cancel();
        }
        self.cancel_poll();
    }

    /// Cancel the reads, and a scan being followed, and leave the writes to
    /// run to their end.
    fn cancel_reads(&self) {
        for entry in self.queue().iter().filter(|entry| !entry.changes_device) {
            entry.operation.cancel();
        }
        self.cancel_poll();
    }

    fn poll(&self) -> MutexGuard<'_, Option<Arc<Operation>>> {
        self.poll.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stop following a scan, if one is followed.
    fn cancel_poll(&self) {
        if let Some(poll) = self.poll().take() {
            poll.cancel();
        }
    }

    /// Follow a new scan under `poll`, ending the one followed before.
    fn start_poll(&self, poll: Arc<Operation>) {
        if let Some(previous) = self.poll().replace(poll) {
            previous.cancel();
        }
    }

    /// `poll`'s scan is no longer followed.
    fn end_poll(&self, poll: &Arc<Operation>) {
        let mut current = self.poll();
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, poll))
        {
            *current = None;
        }
    }
}

/// What an engine is keyed by: one engine per link and target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum EngineKey {
    /// A mesh device, by its canonical address.
    Mesh(String),
    /// The attached radio, by its driver's identity.
    Companion(usize),
    /// A device native code administers, by its driver's identity.
    Administrative(usize),
    #[cfg(test)]
    Scripted(usize),
}

/// Why an engine takes no more commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app_core) enum Retired {
    /// The core stopped.
    Stopped,
    /// The core erased its identity.
    Erased,
}

impl Retired {
    /// What an operation the retirement ended answers.
    fn error(self) -> MobileAppError {
        match self {
            Self::Stopped => MobileAppError::Stopped,
            Self::Erased => MobileAppError::Busy,
        }
    }
}

/// The worker's managed devices.
#[derive(Default)]
pub(in crate::app_core) struct Registry {
    engines: HashMap<u64, Rc<Engine>>,
    keys: HashMap<EngineKey, u64>,
}

impl Registry {
    pub(super) fn engine(&self, id: u64) -> Option<Rc<Engine>> {
        self.engines.get(&id).cloned()
    }

    pub(super) fn all(&self) -> Vec<Rc<Engine>> {
        self.engines.values().cloned().collect()
    }

    /// The live engine for `key`, if one may still take commands for the
    /// core's current owner.
    pub(super) fn live(&self, key: &EngineKey, owner: Option<&String>) -> Option<Rc<Engine>> {
        self.keys
            .get(key)
            .and_then(|id| self.engines.get(id))
            .filter(|engine| engine.current(owner))
            .cloned()
    }

    pub(super) fn insert(&mut self, engine: Rc<Engine>) {
        self.keys.insert(engine.key.clone(), engine.id);
        self.engines.insert(engine.id, engine);
    }

    /// Forget `engine`'s key, so the next `manage_*` for it makes a new
    /// one.
    fn unkey(&mut self, engine: &Engine) {
        if self.keys.get(&engine.key) == Some(&engine.id) {
            self.keys.remove(&engine.key);
        }
    }

    fn remove(&mut self, engine: &Engine) {
        self.unkey(engine);
        self.engines.remove(&engine.id);
    }

    /// How many engines are registered.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.engines.len()
    }
}

/// The engine's own state. Never borrowed across an await.
struct State {
    /// What the cache is keyed by, once known.
    address: Option<String>,
    card: Option<UlcpDeviceCardRecord>,
    card_as_of_ms: Option<i64>,
    card_is_fresh: bool,
    readings: Vec<Reading>,
    /// The values each category's last write was refused.
    refusals: Vec<(UlcpManageCategory, BTreeMap<u32, MobileRefusal>)>,
    alert: UlcpAlertState,
    entered_dfu: bool,
    problem: Option<Problem>,
    phone_node_key: Option<Vec<u8>>,
    /// What a scan heard, by BSSID.
    scan: BTreeMap<Vec<u8>, UlcpWifiScanResultRecord>,
    /// Every handle closed: reads are refused, writes run to their end.
    relinquished: bool,
    next_revision: u64,
}

impl State {
    fn revision(&mut self) -> u64 {
        self.next_revision += 1;
        self.next_revision
    }

    fn reading(&self, category: UlcpManageCategory) -> Option<&Reading> {
        self.readings
            .iter()
            .find(|reading| reading.category == category)
    }

    fn set_reading(&mut self, reading: Reading) {
        match self
            .readings
            .iter_mut()
            .find(|held| held.category == reading.category)
        {
            Some(held) => *held = reading,
            None => self.readings.push(reading),
        }
    }

    fn refusals(&self, category: UlcpManageCategory) -> Option<&BTreeMap<u32, MobileRefusal>> {
        self.refusals
            .iter()
            .find(|(held, _)| *held == category)
            .map(|(_, refusals)| refusals)
    }

    fn set_refusals(
        &mut self,
        category: UlcpManageCategory,
        refusals: BTreeMap<u32, MobileRefusal>,
    ) {
        self.refusals.retain(|(held, _)| *held != category);
        if !refusals.is_empty() {
            self.refusals.push((category, refusals));
        }
    }

    /// Replace `category`'s refusals of `written` with `refused`, keeping
    /// those of every other property.
    fn rewrite_refusals(
        &mut self,
        category: UlcpManageCategory,
        written: &[u32],
        refused: BTreeMap<u32, MobileRefusal>,
    ) {
        let mut refusals = self.refusals(category).cloned().unwrap_or_default();
        refusals.retain(|property, _| !written.contains(property));
        refusals.extend(refused);
        self.set_refusals(category, refusals);
    }

    /// Fold reported values into every reading that covers them, fresh,
    /// at `instant`. Answers whether any reading did.
    fn fold(&mut self, values: &BTreeMap<u32, Vec<u8>>, instant: i64) -> bool {
        let mut affected = false;
        for index in 0..self.readings.len() {
            let covered: BTreeMap<u32, Vec<u8>> = values
                .iter()
                .filter(|(property, _)| self.readings[index].covers(**property))
                .map(|(property, value)| (*property, value.clone()))
                .collect();
            if covered.is_empty() {
                continue;
            }
            affected = true;
            let revision = self.revision();
            self.readings[index].absorb(&covered, instant, true, &BTreeMap::new(), revision);
        }
        affected
    }
}

/// An outcome a command answers, built from how its operation stopped.
pub(super) trait Ended {
    fn from_stop(stop: Stop) -> Self;
    fn is_cancelled(&self) -> bool;
}

impl Ended for MobileManagementOutcome {
    fn from_stop(stop: Stop) -> Self {
        match stop {
            Stop::Cancelled => Self::Cancelled,
            Stop::Skipped => Self::Skipped,
            Stop::Problem(problem) => Self::Failed { problem },
        }
    }

    fn is_cancelled(&self) -> bool {
        *self == Self::Cancelled
    }
}

impl Ended for MobileWifiOutcome {
    fn from_stop(stop: Stop) -> Self {
        match stop {
            Stop::Cancelled => Self::Cancelled,
            Stop::Skipped => Self::Skipped,
            Stop::Problem(problem) => Self::Failed { problem },
        }
    }

    fn is_cancelled(&self) -> bool {
        *self == Self::Cancelled
    }
}

impl Ended for MobileApplyOutcome {
    fn from_stop(stop: Stop) -> Self {
        Self {
            answered: false,
            result: match stop {
                Stop::Cancelled => MobileApplyResult::Cancelled,
                Stop::Skipped => MobileApplyResult::Skipped,
                Stop::Problem(problem) => MobileApplyResult::Failed { problem },
            },
        }
    }

    fn is_cancelled(&self) -> bool {
        self.result == MobileApplyResult::Cancelled
    }
}

/// A table edit the device refused, as its refusal; anything else that
/// stopped it stops the command.
fn refusal_of(result: Result<(), Stop>) -> Result<Option<MobileRefusal>, Stop> {
    match result {
        Ok(()) => Ok(None),
        Err(Stop::Problem(Problem::Refused { refusal })) => Ok(Some(refusal)),
        Err(stop) => Err(stop),
    }
}

fn outcome(result: Result<(), Stop>) -> MobileManagementOutcome {
    result.map_or_else(MobileManagementOutcome::from_stop, |()| {
        MobileManagementOutcome::Done
    })
}

/// What an apply's result means to a command that answers a plain
/// outcome.
fn applied(outcome: &MobileApplyOutcome) -> MobileManagementOutcome {
    match &outcome.result {
        MobileApplyResult::Applied | MobileApplyResult::NothingToApply => {
            MobileManagementOutcome::Done
        }
        MobileApplyResult::Refused => MobileManagementOutcome::Failed {
            problem: Problem::NotAllApplied { saving: false },
        },
        MobileApplyResult::Invalid => MobileManagementOutcome::Failed {
            problem: Problem::InvalidRequest,
        },
        MobileApplyResult::Cancelled => MobileManagementOutcome::Cancelled,
        MobileApplyResult::Skipped => MobileManagementOutcome::Skipped,
        MobileApplyResult::Failed { problem } => MobileManagementOutcome::Failed {
            problem: problem.clone(),
        },
    }
}

/// The values in `answers`, by property.
fn values(answers: &[MobileMeshManagementAnswerRecord]) -> BTreeMap<u32, Vec<u8>> {
    answers
        .iter()
        .filter_map(|answer| Some((answer.property_id, answer.value.clone()?)))
        .collect()
}

pub(super) struct Engine {
    pub(super) id: u64,
    key: EngineKey,
    pub(super) link: MobileManagementLink,
    uses_bluetooth: bool,
    pub(super) carrier: Carrier,
    /// The owner whose cache this engine reads and writes, or `None` for
    /// a storeless one. Another owner retires it.
    owner: Option<String>,
    handles: RefCell<BTreeSet<u64>>,
    state: RefCell<State>,
    /// Raised when an entry leaves the queue.
    turn: Notify,
    pub(super) published: Arc<Published>,
    retired: Cell<Option<Retired>>,
}

impl Engine {
    pub(super) fn new(
        key: EngineKey,
        link: MobileManagementLink,
        uses_bluetooth: bool,
        carrier: Carrier,
        owner: Option<String>,
        address: Option<String>,
    ) -> Rc<Self> {
        let id = next_id();
        let state = State {
            address,
            card: None,
            card_as_of_ms: None,
            card_is_fresh: false,
            readings: Vec::new(),
            refusals: Vec::new(),
            alert: UlcpAlertState::None,
            entered_dfu: false,
            problem: None,
            phone_node_key: None,
            scan: BTreeMap::new(),
            relinquished: false,
            next_revision: 0,
        };
        let engine = Self {
            id,
            key,
            link,
            uses_bluetooth,
            carrier,
            owner,
            handles: RefCell::new(BTreeSet::new()),
            state: RefCell::new(state),
            turn: Notify::new(),
            published: Arc::new(Published {
                record: Mutex::new(MobileManagedDeviceRecord {
                    revision: 0,
                    link,
                    uses_bluetooth,
                    address: None,
                    card: None,
                    card_as_of_ms: None,
                    card_is_fresh: false,
                    categories: Vec::new(),
                    readings: Vec::new(),
                    alert: UlcpAlertState::None,
                    busy: false,
                    entered_dfu: false,
                    problem: None,
                    phone_node_key: None,
                    heard_networks: Vec::new(),
                    refreshes_stale_readings: false,
                    offers_factory_reset: false,
                    phone_stands_for_device: false,
                    supports_wifi_station: false,
                    supports_bluetooth_pairing: false,
                    peers: None,
                    administrators: None,
                }),
                queue: Mutex::new(VecDeque::new()),
                poll: Mutex::new(None),
            }),
            retired: Cell::new(None),
        };
        let record = engine.record();
        *engine
            .published
            .record
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = MobileManagedDeviceRecord {
            revision: 1,
            ..record
        };
        Rc::new(engine)
    }

    /// Whether this engine takes commands for `owner`.
    pub(super) fn current(&self, owner: Option<&String>) -> bool {
        self.retired.get().is_none() && self.owner.as_ref().is_none_or(|mine| Some(mine) == owner)
    }

    /// Off the mesh, a stale or empty reading refreshes itself.
    fn refreshes_stale_readings(&self) -> bool {
        self.link != MobileManagementLink::Mesh
    }

    /// Why a command cannot run now, before it is queued: the engine was
    /// retired, or the core's owner is not the one it reads for.
    pub(super) fn refusal<T: Ended>(&self, worker: &Worker) -> Option<Result<T, MobileAppError>> {
        match self.retired.get() {
            Some(Retired::Stopped) => return Some(Err(MobileAppError::Stopped)),
            Some(Retired::Erased) => {
                return Some(Ok(T::from_stop(Stop::Problem(Problem::NoOwner))));
            }
            None => {}
        }
        if !self.current(worker.owner().as_ref()) {
            return Some(Ok(T::from_stop(Stop::Problem(Problem::NoOwner))));
        }
        None
    }

    /// The error an operation on this engine answers once it was
    /// retired; `None` while it serves.
    pub(super) fn retirement(&self) -> Option<MobileAppError> {
        self.retired.get().map(Retired::error)
    }

    /// How many entries wait on or hold the queue.
    #[cfg(test)]
    pub(super) fn queue_len(&self) -> usize {
        self.published.queue().len()
    }

    /// What a finished operation answers once the engine was retired
    /// under it.
    pub(super) fn ended<T: Ended>(&self, outcome: T) -> Result<T, MobileAppError> {
        match self.retired.get() {
            Some(retired) if outcome.is_cancelled() => Err(retired.error()),
            _ => Ok(outcome),
        }
    }

    // MARK: Handles

    /// A new handle. A device every screen had left takes reads again.
    pub(super) fn open_handle(&self, handle: u64) {
        self.handles.borrow_mut().insert(handle);
        self.state.borrow_mut().relinquished = false;
    }

    /// A handle is done. The last one relinquishes the device: reads are
    /// canceled and refused, writes run to their end, and the engine
    /// leaves the registry once its queue is empty.
    pub(super) fn close_handle(&self, worker: &Worker, handle: u64) {
        let last = {
            let mut handles = self.handles.borrow_mut();
            handles.remove(&handle) && handles.is_empty()
        };
        if !last {
            return;
        }
        self.state.borrow_mut().relinquished = true;
        self.published.cancel_reads();
        self.leave_if_done(worker);
    }

    /// Leave the registry when no handle holds the engine and nothing is
    /// queued.
    fn leave_if_done(&self, worker: &Worker) {
        if self.handles.borrow().is_empty() && self.published.queue().is_empty() {
            worker.managed.borrow_mut().remove(self);
        }
    }

    /// Take no more commands: everything queued is canceled and answers
    /// what `retired` says.
    pub(super) fn retire(&self, worker: &Worker, retired: Retired) {
        self.retired.set(Some(retired));
        self.published.cancel();
        worker.managed.borrow_mut().unkey(self);
        self.leave_if_done(worker);
    }

    // MARK: Publishing

    /// The record as the state says now, at the published revision.
    fn record(&self) -> MobileManagedDeviceRecord {
        let state = self.state.borrow();
        let categories = state
            .card
            .as_ref()
            .map(|card| {
                CATEGORY_ORDER
                    .iter()
                    .filter_map(|category| {
                        let property_ids =
                            ulcp_category_properties(*category, card.capabilities.clone()).ok()?;
                        (!property_ids.is_empty()).then_some(MobileOfferedCategoryRecord {
                            category: *category,
                            property_ids,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let answered = |category, property| {
            state
                .reading(category)
                .is_some_and(|reading: &Reading| reading.answered(property))
        };
        let peer_nodes = state.reading(UlcpManageCategory::PeerNodes);
        let table = |property: u32, keys: Option<&Vec<Vec<u8>>>, administrators: bool| {
            let keys =
                keys.filter(|_| peer_nodes.is_some_and(|reading| reading.answered(property)))?;
            Some(MobileKeyTableRecord {
                entries: keys
                    .iter()
                    .map(|key| {
                        let is_this_phone = state.phone_node_key.as_ref() == Some(key);
                        MobileKeyEntryRecord {
                            key: key.clone(),
                            is_this_phone,
                            removable: !administrators || (!is_this_phone && keys.len() > 1),
                        }
                    })
                    .collect(),
            })
        };
        let properties = peer_nodes.map(|reading| &reading.properties);
        MobileManagedDeviceRecord {
            revision: self.published.record().revision,
            link: self.link,
            uses_bluetooth: self.uses_bluetooth,
            // Only what a cache is kept under: a device with no owner to
            // keep one for is storeless.
            address: self.owner.as_ref().and(state.address.clone()),
            card: state.card.clone(),
            card_as_of_ms: state.card_as_of_ms,
            card_is_fresh: state.card_is_fresh,
            categories,
            readings: state
                .readings
                .iter()
                .map(|reading| reading.record(state.refusals(reading.category)))
                .collect(),
            alert: state.alert,
            busy: !self.published.queue().is_empty(),
            entered_dfu: state.entered_dfu,
            problem: state.problem.clone(),
            phone_node_key: state.phone_node_key.clone(),
            heard_networks: heard_networks(&state),
            refreshes_stale_readings: self.refreshes_stale_readings(),
            offers_factory_reset: self.link != MobileManagementLink::Mesh,
            phone_stands_for_device: self.link != MobileManagementLink::Mesh,
            supports_wifi_station: answered(UlcpManageCategory::Wifi, prop::WIFI_ENABLED),
            supports_bluetooth_pairing: answered(
                UlcpManageCategory::Bluetooth,
                prop::BLE_BOND_COUNT,
            ),
            peers: table(
                prop::DEV_PEERS,
                properties.and_then(|properties| properties.dev_peer_keys.as_ref()),
                false,
            ),
            administrators: table(
                prop::DEV_ADMINS,
                properties.and_then(|properties| properties.dev_admin_keys.as_ref()),
                true,
            ),
        }
    }

    /// Publish the record when it changed, then say so in the changes.
    pub(super) fn publish(&self, worker: &Worker) {
        let record = self.record();
        let changed = {
            let mut published = self
                .published
                .record
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *published == record {
                false
            } else {
                *published = MobileManagedDeviceRecord {
                    revision: record.revision + 1,
                    ..record
                };
                true
            }
        };
        if changed {
            worker.raise(MobileAppChangesRecord {
                managed_devices: vec![self.id],
                ..MobileAppChangesRecord::default()
            });
        }
    }

    // MARK: The queue

    fn queued(&self, read: Read) -> bool {
        self.published
            .queue()
            .iter()
            .any(|entry| entry.read == Some(read))
    }

    /// Whether a read of `read` waits in the queue behind the one running.
    fn waiting(&self, read: Read) -> bool {
        self.published
            .queue()
            .iter()
            .skip(1)
            .any(|entry| entry.read == Some(read))
    }

    /// Run `body` once everything asked before it has finished. Once the
    /// engine is retired nothing more is queued, and answers `Cancelled`
    /// as what `retire` canceled does. After firmware update entry
    /// nothing runs, and once every handle closed only what changes the
    /// device does; both answer `Skipped`. A failure is the device's
    /// problem until the next thing is asked.
    pub(super) async fn run<T, Fut>(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        changes_device: bool,
        read: Option<Read>,
        body: impl FnOnce(Arc<Operation>) -> Fut,
    ) -> Result<T, Stop>
    where
        Fut: Future<Output = Result<T, Stop>>,
    {
        if self.retired.get().is_some() {
            return Err(Stop::Cancelled);
        }
        {
            let mut state = self.state.borrow_mut();
            if state.entered_dfu || (state.relinquished && !changes_device) {
                return Err(Stop::Skipped);
            }
            // Asking again is what an operator does about the last failure.
            state.problem = None;
        }
        let id = next_id();
        let operation = Operation::new();
        self.published.queue().push_back(Entry {
            id,
            changes_device,
            read,
            operation: operation.clone(),
        });
        self.publish(worker);
        loop {
            let turn = self.turn.notified();
            tokio::pin!(turn);
            turn.as_mut().enable();
            if self
                .published
                .queue()
                .front()
                .is_some_and(|entry| entry.id == id)
            {
                break;
            }
            turn.await;
        }
        let result = if operation.check().is_err() {
            Err(Stop::Cancelled)
        } else if self.state.borrow().entered_dfu {
            Err(Stop::Skipped)
        } else {
            body(operation).await
        };
        self.published.queue().retain(|entry| entry.id != id);
        self.turn.notify_waiters();
        if let Err(Stop::Problem(problem)) = &result {
            self.state.borrow_mut().problem = Some(problem.clone());
        }
        self.publish(worker);
        self.leave_if_done(worker);
        result
    }

    // MARK: The store

    /// Whose cache, under which address, when this device has one.
    fn cache_target(&self) -> Option<(String, String)> {
        Some((self.owner.clone()?, self.state.borrow().address.clone()?))
    }

    fn stored_card(&self, worker: &Worker) -> Option<MobileStoredManagementCardRecord> {
        let (owner, address) = self.cache_target()?;
        worker
            .store
            .management_card(owner, address)
            .inspect_err(
                |error| log::warn!(error:? = error; "a managed device's card was not read"),
            )
            .ok()
            .flatten()
    }

    fn save_card(&self, worker: &Worker, card: MobileStoredManagementCardRecord) {
        let Some((owner, address)) = self.cache_target() else {
            return;
        };
        if let Err(error) = worker.store.save_management_card(owner, address, card) {
            log::warn!(error:? = error; "a managed device's card was not kept");
        }
    }

    fn cached(&self, worker: &Worker, property_ids: Vec<u32>) -> BTreeMap<u32, (Vec<u8>, i64)> {
        let Some((owner, address)) = self.cache_target() else {
            return BTreeMap::new();
        };
        match worker.store.cached_properties(owner, address, property_ids) {
            Ok(cached) => cached
                .into_iter()
                .map(|(property, cached)| (property, (cached.value, cached.fetched_at_ms)))
                .collect(),
            Err(error) => {
                log::warn!(error:? = error; "a managed device's values were not read");
                BTreeMap::new()
            }
        }
    }

    /// Keep what the device reported, minus what is always read fresh.
    fn cache(&self, worker: &Worker, values: &BTreeMap<u32, Vec<u8>>) {
        let keepable: HashMap<u32, Vec<u8>> = values
            .iter()
            .filter(|(property, _)| persistent(**property))
            .map(|(property, value)| (*property, value.clone()))
            .collect();
        if keepable.is_empty() {
            return;
        }
        let Some((owner, address)) = self.cache_target() else {
            return;
        };
        if let Err(error) =
            worker
                .store
                .save_cached_properties(owner, address, keepable, worker.clock.now_ms())
        {
            log::warn!(error:? = error; "a managed device's values were not kept");
        }
    }

    // MARK: The card

    /// The attached radio's own identity, once it reports one, is what its
    /// cache is kept under.
    fn learn_address(&self) {
        if self.state.borrow().address.is_some() {
            return;
        }
        let Some(driver) = self.carrier.driver() else {
            return;
        };
        let address = driver
            .state()
            .device_key
            .and_then(|key| crate::inspect_public_identity_bytes(key).ok())
            .map(|identity| identity.canonical_address);
        self.state.borrow_mut().address = address;
    }

    /// Learn this phone's key afresh: a storeless engine outlives an owner
    /// set after it was made.
    fn learn_phone_node_key(&self, worker: &Worker) {
        let key = self.carrier.phone_node_key(worker);
        self.state.borrow_mut().phone_node_key = key;
    }

    /// Fill the card in from the cache, and ask the device when there is
    /// still none, or off the mesh when it has not come off the air
    /// during this engine's lifetime.
    pub(super) async fn load_card(self: &Rc<Self>, worker: &Rc<Worker>) -> MobileManagementOutcome {
        self.learn_address();
        self.learn_phone_node_key(worker);
        if self.state.borrow().card.is_none()
            && let Some(stored) = self.stored_card(worker)
        {
            self.adopt(stored);
        }
        self.publish(worker);
        let wanted = {
            let state = self.state.borrow();
            state.card.is_none() || (self.refreshes_stale_readings() && !state.card_is_fresh)
        };
        if wanted && !self.queued(Read::Card) {
            return self.refresh_card(worker).await;
        }
        MobileManagementOutcome::Done
    }

    /// Rebuild the card from what the store kept. A blob this build
    /// cannot decode is ignored, and only asking the device repairs it.
    fn adopt(&self, stored: MobileStoredManagementCardRecord) {
        let Ok(decoded) =
            inspect_ulcp_device_card(vec![ulcp_property_record(prop::CAPS, stored.capabilities)])
        else {
            return;
        };
        let mut state = self.state.borrow_mut();
        state.card = Some(UlcpDeviceCardRecord {
            device_version: stored.device_version,
            device_model: stored.device_model,
            device_name: stored.device_name,
            ..decoded
        });
        state.card_as_of_ms = Some(stored.fetched_at_ms);
    }

    /// Ask the device what it is.
    pub(super) async fn refresh_card(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, false, Some(Read::Card), |operation| async move {
                let answers = engine
                    .carrier
                    .fetch(&worker_, &operation, ulcp_card_properties(), true)
                    .await?;
                let fetched = inspect_ulcp_device_card(
                    crate::mobile_mesh::ulcp_records_from_answers(answers),
                )
                .map_err(|_| Stop::Problem(Problem::Unreadable))?;
                let now = worker_.clock.now_ms();
                engine.save_card(
                    &worker_,
                    MobileStoredManagementCardRecord {
                        capabilities: fetched.capabilities.clone(),
                        device_version: fetched.device_version.clone(),
                        device_model: fetched.device_model.clone(),
                        device_name: fetched.device_name.clone(),
                        fetched_at_ms: now,
                    },
                );
                let mut state = engine.state.borrow_mut();
                // Other firmware may hold other properties: the store drops
                // the values, and this drops what is on screen.
                if state.card.as_ref().map(|card| &card.device_version)
                    != Some(&fetched.device_version)
                {
                    state.readings.clear();
                    state.refusals.clear();
                }
                state.card = Some(fetched);
                state.card_as_of_ms = Some(now);
                state.card_is_fresh = true;
                Ok(())
            })
            .await,
        )
    }

    // MARK: Categories

    /// What `category` covers on this device; empty without a card.
    fn properties_of(&self, category: UlcpManageCategory) -> Vec<u32> {
        self.state
            .borrow()
            .card
            .as_ref()
            .and_then(|card| ulcp_category_properties(category, card.capabilities.clone()).ok())
            .unwrap_or_default()
    }

    /// Fill a category in from the cache, and off the mesh follow with a
    /// read when nothing of it has come off the air during this engine's
    /// lifetime.
    pub(super) async fn load_category(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        category: UlcpManageCategory,
    ) -> MobileManagementOutcome {
        if self.state.borrow().reading(category).is_none() {
            let property_ids = self.properties_of(category);
            if property_ids.is_empty() {
                return MobileManagementOutcome::Done;
            }
            let cached = self.cached(
                worker,
                property_ids
                    .iter()
                    .copied()
                    .filter(|property| persistent(*property))
                    .collect(),
            );
            let mut state = self.state.borrow_mut();
            let revision = state.revision();
            let mut reading = Reading::new(category, property_ids, revision);
            if let Some(oldest) = cached.values().map(|(_, at)| *at).min() {
                let values = cached
                    .iter()
                    .map(|(property, (value, _))| (*property, value.clone()))
                    .collect();
                let instants = cached
                    .iter()
                    .map(|(property, (_, at))| (*property, *at))
                    .collect();
                reading.absorb(&values, oldest, false, &instants, revision);
            }
            state.set_reading(reading);
        }
        self.publish(worker);
        let stale = self
            .state
            .borrow()
            .reading(category)
            .is_some_and(|reading| !reading.is_fresh);
        if self.refreshes_stale_readings() && stale && !self.queued(Read::Category(category)) {
            return self.refresh_category(worker, category).await;
        }
        MobileManagementOutcome::Done
    }

    /// Ask the device for one category. The reading is replaced, not
    /// merged: a refusal means the device does not hold that property.
    pub(super) async fn refresh_category(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        category: UlcpManageCategory,
    ) -> MobileManagementOutcome {
        let property_ids = self.properties_of(category);
        let Some(multi_hint) = self
            .state
            .borrow()
            .card
            .as_ref()
            .map(|card| card.supports_multi)
        else {
            return MobileManagementOutcome::Done;
        };
        if property_ids.is_empty() {
            return MobileManagementOutcome::Done;
        }
        self.state
            .borrow_mut()
            .set_refusals(category, BTreeMap::new());
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(
                worker,
                false,
                Some(Read::Category(category)),
                |operation| async move {
                    if category == UlcpManageCategory::Sensors {
                        return engine
                            .refresh_sensors(&worker_, &operation, property_ids)
                            .await;
                    }
                    let answers = engine
                        .carrier
                        .fetch(&worker_, &operation, property_ids.clone(), multi_hint)
                        .await?;
                    let reported = values(&answers);
                    engine.cache(&worker_, &reported);
                    let now = worker_.clock.now_ms();
                    let mut state = engine.state.borrow_mut();
                    let revision = state.revision();
                    let mut reading = Reading::new(category, property_ids, revision);
                    for answer in answers.iter().filter(|answer| answer.value.is_none()) {
                        reading.refused.insert(answer.property_id);
                        if let Some(status) = answer.status_code {
                            reading.statuses.insert(answer.property_id, status);
                        }
                    }
                    reading.absorb(&reported, now, true, &BTreeMap::new(), revision);
                    state.set_reading(reading);
                    Ok(())
                },
            )
            .await,
        )
    }

    /// The sensors, in as few requests as their names allow. Names are
    /// kept across a refresh until a measurement reveals more sensors; a
    /// failed request marks its own properties and the next one still
    /// goes. Published before the first request and after each. Nothing
    /// is cached.
    async fn refresh_sensors(
        &self,
        worker: &Rc<Worker>,
        operation: &Operation,
        property_ids: Vec<u32>,
    ) -> Result<(), Stop> {
        let mut reading = {
            let mut state = self.state.borrow_mut();
            let revision = state.revision();
            let reading = Reading::sensor_refresh(
                state.reading(UlcpManageCategory::Sensors),
                property_ids,
                revision,
            );
            state.set_reading(reading.clone());
            reading
        };
        self.publish(worker);
        for requested in reading.sensor_requests() {
            if requested == [prop::TEMPERATURE_NAMES] && !reading.needs_temperature_names() {
                continue;
            }
            match self
                .carrier
                .fetch(worker, operation, requested.clone(), true)
                .await
            {
                Ok(answers) => {
                    let now = worker.clock.now_ms();
                    for answer in answers.iter().filter(|answer| answer.value.is_none()) {
                        reading.refused.insert(answer.property_id);
                        if let Some(status) = answer.status_code {
                            reading.statuses.insert(answer.property_id, status);
                        }
                    }
                    let mut reported = values(&answers);
                    for property in &requested {
                        if !reported.contains_key(property) && !reading.refused.contains(property) {
                            reading.failures.insert(*property, Failure::NoResponse);
                        }
                    }
                    let names = reported.remove(&prop::TEMPERATURE_NAMES);
                    let revision = self.state.borrow_mut().revision();
                    reading.absorb(&reported, now, true, &BTreeMap::new(), revision);
                    if let Some(names) = names {
                        reading.absorb_temperature_names(names, now, revision);
                    }
                }
                Err(Stop::Problem(problem)) => {
                    for property in &requested {
                        reading
                            .failures
                            .insert(*property, Failure::Failed(problem.clone()));
                    }
                    reading.revision = self.state.borrow_mut().revision();
                }
                Err(stop) => return Err(stop),
            }
            self.state.borrow_mut().set_reading(reading.clone());
            self.publish(worker);
        }
        Ok(())
    }

    // MARK: Writes

    /// Apply a draft: rebased and folded now, on the state as it stands,
    /// before anything is queued, so a queued apply writes what the draft
    /// said when Apply was tapped.
    pub(super) async fn apply_draft(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        draft: MobileManagementDraft,
    ) -> MobileApplyOutcome {
        self.note("applied a managed device's settings");
        let prepared = match draft::prepare(&self.record(), draft) {
            Ok(prepared) => prepared,
            Err(_) => {
                return MobileApplyOutcome {
                    answered: false,
                    result: MobileApplyResult::Failed {
                        problem: Problem::InvalidRequest,
                    },
                };
            }
        };
        if !prepared.problems.is_empty() {
            return MobileApplyOutcome {
                answered: false,
                result: MobileApplyResult::Invalid,
            };
        }
        self.apply_properties(
            worker,
            prepared.category,
            prepared.desired,
            prepared.dirty,
            true,
        )
        .await
    }

    /// Write the dirty properties of `desired`, fold what the device
    /// echoes, and save unless it refused any.
    ///
    /// `answered` once the device answered the write, even when it refused
    /// a value or the save then failed.
    pub(super) async fn apply_properties(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        category: UlcpManageCategory,
        desired: UlcpDevicePropertiesRecord,
        mut dirty: Vec<u32>,
        save: bool,
    ) -> MobileApplyOutcome {
        if dirty.is_empty() {
            return MobileApplyOutcome {
                answered: true,
                result: MobileApplyResult::NothingToApply,
            };
        }
        dirty.sort_unstable();
        dirty.dedup();
        // Refusals of what is written now are stale; others still stand.
        self.state
            .borrow_mut()
            .rewrite_refusals(category, &dirty, BTreeMap::new());
        let written = dirty.clone();
        let answered = Rc::new(Cell::new(false));
        let engine = self.clone();
        let worker_ = worker.clone();
        let answered_ = answered.clone();
        let result = self
            .run(worker, true, None, |operation| async move {
                let writes = ulcp_dirty_writes(desired, dirty)
                    .map_err(|_| Stop::Problem(Problem::NotBuilt))?;
                let answers = engine.carrier.write(&worker_, &operation, writes).await?;
                answered_.set(true);
                let echoed = values(&answers);
                engine.cache(&worker_, &echoed);
                let now = worker_.clock.now_ms();
                engine.state.borrow_mut().fold(&echoed, now);
                // A status where a value belonged is a value the device
                // would not take; nothing is saved then.
                let refusals: BTreeMap<u32, MobileRefusal> = answers
                    .iter()
                    .filter(|answer| answer.value.is_none())
                    .map(|answer| (answer.property_id, classify(answer.status_code)))
                    .collect();
                if !refusals.is_empty() {
                    let mut state = engine.state.borrow_mut();
                    state.rewrite_refusals(category, &written, refusals);
                    state.problem = Some(Problem::NotAllApplied { saving: save });
                    return Ok(MobileApplyResult::Refused);
                }
                if save {
                    engine.carrier.save(&worker_, &operation).await?;
                }
                Ok(MobileApplyResult::Applied)
            })
            .await;
        let mut outcome =
            result.map_or_else(MobileApplyOutcome::from_stop, |result| MobileApplyOutcome {
                answered: true,
                result,
            });
        outcome.answered = answered.get();
        outcome
    }

    /// Set the device's clock to now, unsaved: a clock staged for later
    /// would be wrong by then.
    pub(super) async fn set_clock_now(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        self.note("set a managed device's clock");
        let mut desired = self
            .state
            .borrow()
            .reading(UlcpManageCategory::Time)
            .map(|reading| reading.properties.clone())
            .unwrap_or_default();
        desired.time = Some(clock_now(worker));
        let outcome = self
            .apply_properties(
                worker,
                UlcpManageCategory::Time,
                desired,
                vec![prop::TIME],
                false,
            )
            .await;
        applied(&outcome)
    }

    /// Zero the counters the Statistics reading answered, unsaved, then
    /// read them again when the device answered.
    pub(super) async fn reset_counters(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        self.note("reset a managed device's counters");
        let counters: Vec<u32> = {
            let state = self.state.borrow();
            let Some(reading) = state.reading(UlcpManageCategory::Statistics) else {
                return MobileManagementOutcome::Done;
            };
            reading.resettable_counters()
        };
        if counters.is_empty() {
            return MobileManagementOutcome::Done;
        }
        let outcome = self
            .apply_properties(
                worker,
                UlcpManageCategory::Statistics,
                UlcpDevicePropertiesRecord::default(),
                counters,
                false,
            )
            .await;
        let result = applied(&outcome);
        if !outcome.answered {
            return result;
        }
        // Read again even when some were refused: the ones accepted are
        // zero now. A refusal stays the answer.
        let refreshed = self
            .refresh_category(worker, UlcpManageCategory::Statistics)
            .await;
        if result == MobileManagementOutcome::Done {
            refreshed
        } else {
            result
        }
    }

    // MARK: Actions

    /// Make the device conspicuous, or stop. Over the mesh the device's
    /// echo says what it is doing; a local link answers by push, so the
    /// request stands until one arrives.
    pub(super) async fn set_alert(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        requested: UlcpAlertState,
    ) -> MobileManagementOutcome {
        self.note("changed a managed device's locate alert");
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, true, None, |operation| async move {
                let reported = engine
                    .carrier
                    .set_alert(&worker_, &operation, requested)
                    .await?;
                engine.state.borrow_mut().alert = reported.unwrap_or(requested);
                Ok(())
            })
            .await,
        )
    }

    /// Put the device into firmware update. Once it confirms, nothing
    /// queued after runs.
    pub(super) async fn enter_dfu(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        mode: UlcpDfuMode,
    ) -> MobileManagementOutcome {
        self.note("put a managed device into firmware update");
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, true, None, |operation| async move {
                engine.carrier.enter_dfu(&worker_, &operation, mode).await?;
                engine.state.borrow_mut().entered_dfu = true;
                // Nothing more is asked of it, a scan's progress included.
                engine.published.cancel_poll();
                Ok(())
            })
            .await,
        )
    }

    /// Restart, keeping what the device saved. Its sensor inventory is
    /// read again on the next open.
    pub(super) async fn restart(self: &Rc<Self>, worker: &Rc<Worker>) -> MobileManagementOutcome {
        self.note("restarted a managed device");
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, true, None, |operation| async move {
                engine
                    .carrier
                    .reset(&worker_, &operation, MobileMeshResetScope::Reboot)
                    .await?;
                engine
                    .state
                    .borrow_mut()
                    .readings
                    .retain(|reading| reading.category != UlcpManageCategory::Sensors);
                Ok(())
            })
            .await,
        )
    }

    /// Ask the device to announce itself now.
    pub(super) async fn announce(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        kind: MobileAnnouncementKind,
        reach: MobileAnnouncementReach,
    ) -> MobileManagementOutcome {
        self.note("asked a managed device to announce itself");
        let request = MobileAnnouncementRecord {
            kind,
            flood_hops: match reach {
                MobileAnnouncementReach::Nearby => NEARBY_HOPS,
                MobileAnnouncementReach::Mesh => MESH_HOPS,
            },
            full_source: None,
            channel_identifier: None,
        };
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, true, None, |operation| async move {
                engine.carrier.announce(&worker_, &operation, request).await
            })
            .await,
        )
    }

    /// Return the device to a blank factory state, off the mesh only. It
    /// comes back as another node, so once the reset is sent its cache
    /// goes whatever the outcome: a failed reset may still have reset.
    pub(super) async fn factory_reset(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        self.note("factory reset a managed device");
        if self.link == MobileManagementLink::Mesh {
            self.state.borrow_mut().problem = Some(Problem::InvalidRequest);
            self.publish(worker);
            return MobileManagementOutcome::Failed {
                problem: Problem::InvalidRequest,
            };
        }
        let engine = self.clone();
        let worker_ = worker.clone();
        let sent = Rc::new(Cell::new(false));
        let sent_ = sent.clone();
        let result = outcome(
            self.run(worker, true, None, |operation| async move {
                sent_.set(true);
                engine
                    .carrier
                    .reset(&worker_, &operation, MobileMeshResetScope::Factory)
                    .await
            })
            .await,
        );
        if sent.get() {
            self.forget_cache(worker);
        }
        result
    }

    /// Forget everything cached about the device, so the next open asks
    /// it afresh. The freshness flag, the scan, the alert and the phone's
    /// key stay.
    pub(super) fn forget_cache(&self, worker: &Worker) {
        if let Some((owner, address)) = self.cache_target()
            && let Err(error) = worker.store.forget_management_cache(owner, address)
        {
            log::warn!(error:? = error; "a managed device's cache was not forgotten");
        }
        {
            let mut state = self.state.borrow_mut();
            state.card = None;
            state.card_as_of_ms = None;
            state.readings.clear();
            state.refusals.clear();
        }
        self.publish(worker);
    }

    /// Log an operator's command once, in constant text: never a name,
    /// key, network or address.
    pub(super) fn note(&self, action: &'static str) {
        log::info!(link:? = self.link; "action: user {action}");
    }

    /// Every reading and the card were overtaken by a write made outside
    /// them: off the mesh each reads again on its next load.
    pub(super) fn mark_stale(&self, worker: &Worker) {
        {
            let mut state = self.state.borrow_mut();
            state.card_is_fresh = false;
            for reading in &mut state.readings {
                reading.is_fresh = false;
            }
        }
        self.publish(worker);
    }

    pub(super) fn dismiss_problem(&self, worker: &Worker) {
        self.state.borrow_mut().problem = None;
        self.publish(worker);
    }

    /// A command refused before anything is asked: the problem is shown
    /// and answered.
    fn refuse_now(&self, worker: &Worker, problem: Problem) -> Stop {
        self.state.borrow_mut().problem = Some(problem.clone());
        self.publish(worker);
        Stop::Problem(problem)
    }

    // MARK: Writes outside a draft

    /// Write what a button stands for. Echoes fold into every reading that
    /// lists them and are kept by the cache's rule. Answers the first value
    /// the device would not take, by property.
    async fn write_echoed(
        &self,
        worker: &Worker,
        operation: &Operation,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<Option<(u32, MobileRefusal)>, Stop> {
        let answers = self.carrier.write(worker, operation, writes).await?;
        let echoed = values(&answers);
        self.cache(worker, &echoed);
        let now = worker.clock.now_ms();
        self.state.borrow_mut().fold(&echoed, now);
        Ok(answers
            .iter()
            .find(|answer| answer.value.is_none())
            .map(|answer| (answer.property_id, classify(answer.status_code))))
    }

    /// [`Self::write_echoed`] as its own entry; a value refused is the
    /// failure.
    async fn button_write(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> MobileManagementOutcome {
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, true, None, |operation| async move {
                match engine.write_echoed(&worker_, &operation, writes).await? {
                    Some((_, refusal)) => Err(Stop::Problem(Problem::Refused { refusal })),
                    None => Ok(()),
                }
            })
            .await,
        )
    }

    // MARK: Key tables

    /// The key table the reading holds now; unread, it is empty.
    fn key_table(&self, table: MobileKeyTable) -> Vec<Vec<u8>> {
        self.state
            .borrow()
            .reading(UlcpManageCategory::PeerNodes)
            .and_then(|reading| match table {
                MobileKeyTable::Peers => reading.properties.dev_peer_keys.clone(),
                MobileKeyTable::Administrators => reading.properties.dev_admin_keys.clone(),
            })
            .unwrap_or_default()
    }

    /// Bring one of the device's key tables to `desired`. The edits are
    /// what `desired` changes in the table as it reads now; they are made
    /// to the table as it reads when this command's turn comes, so edits
    /// queued one behind another all take. This phone's own administrator
    /// entry, and the last administrator, are never taken out. The table
    /// is then the one the edits leave, without reading it back.
    pub(super) async fn set_keys(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        table: MobileKeyTable,
        desired: Vec<Vec<u8>>,
    ) -> MobileManagementOutcome {
        self.note("edited a managed device's key table");
        let asked = key_table_diff(&self.key_table(table), &desired);
        if asked.is_empty() {
            return MobileManagementOutcome::Done;
        }
        let property = match table {
            MobileKeyTable::Peers => prop::DEV_PEERS,
            MobileKeyTable::Administrators => prop::DEV_ADMINS,
        };
        let category_ids = self.properties_of(UlcpManageCategory::PeerNodes);
        let engine = self.clone();
        let worker_ = worker.clone();
        outcome(
            self.run(worker, true, None, |operation| async move {
                let current = engine.key_table(table);
                let (edits, after) = asked.against(&current);
                if edits.is_empty() {
                    return Ok(());
                }
                if table == MobileKeyTable::Administrators {
                    let phone = engine.state.borrow().phone_node_key.clone();
                    let removes_this_phone = phone
                        .as_ref()
                        .is_some_and(|phone| edits.removals.contains(phone));
                    let empties = !current.is_empty() && after.is_empty();
                    if removes_this_phone || empties {
                        return Err(Stop::Problem(Problem::InvalidRequest));
                    }
                }
                apply_key_table(&engine.carrier, &worker_, &operation, table, &edits).await?;
                // A local link's session already saved behind each edit.
                if !engine.carrier.saves_table_edits() {
                    engine.carrier.save(&worker_, &operation).await?;
                }
                let values = BTreeMap::from([(property, after.into_iter().flatten().collect())]);
                engine.cache(&worker_, &values);
                let now = worker_.clock.now_ms();
                let mut state = engine.state.borrow_mut();
                let revision = state.revision();
                let mut reading = state
                    .reading(UlcpManageCategory::PeerNodes)
                    .cloned()
                    .unwrap_or_else(|| {
                        Reading::new(UlcpManageCategory::PeerNodes, category_ids, revision)
                    });
                reading.absorb(&values, now, true, &BTreeMap::new(), revision);
                state.set_reading(reading);
                Ok(())
            })
            .await,
        )
    }

    // MARK: Wi-Fi

    /// Ask the device to look for networks. A local link reports what it
    /// hears as it hears it; across the mesh nothing is pushed, so the
    /// scan flag is read until it clears, and the table with it. Returns
    /// when the scan is no longer followed. A second scan ends the first.
    pub(super) async fn scan_networks(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        let poll = Operation::new();
        self.published.start_poll(poll.clone());
        self.state.borrow_mut().scan.clear();
        self.publish(worker);
        let written = self
            .button_write(
                worker,
                vec![MobileMeshPropertyWriteRecord {
                    property_id: prop::WIFI_SCANNING,
                    value: vec![1],
                }],
            )
            .await;
        let result = if written == MobileManagementOutcome::Done
            && self.link == MobileManagementLink::Mesh
        {
            self.follow_scan(worker, &poll).await
        } else {
            written
        };
        self.published.end_poll(&poll);
        result
    }

    /// Read the scan flag every [`SCAN_POLL_STEP_MS`] until the device
    /// says it stopped, then take the table it heard. A failed read ends
    /// the scan with its problem. Bounded: a device that never clears the
    /// flag within [`SCAN_POLL_ROUNDS`] is given up on, silently.
    async fn follow_scan(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        poll: &Operation,
    ) -> MobileManagementOutcome {
        for _ in 0..SCAN_POLL_ROUNDS {
            let deadline = worker.clock.monotonic_ms() + SCAN_POLL_STEP_MS;
            tokio::select! {
                biased;
                () = poll.wait_cancelled() => {}
                () = worker.clock.sleep_until(deadline) => {}
            }
            if let Some(ended) = self.poll_ended(poll) {
                return ended;
            }
            let refreshed = self
                .refresh_category(worker, UlcpManageCategory::Wifi)
                .await;
            // The read does not run under the poll: a scan started while
            // it was out must not have its cleared table loaded over.
            if let Some(ended) = self.poll_ended(poll) {
                return ended;
            }
            if refreshed != MobileManagementOutcome::Done {
                return refreshed;
            }
            let finished = {
                let mut state = self.state.borrow_mut();
                let reading = state.reading(UlcpManageCategory::Wifi);
                let scanning = reading.and_then(|reading| reading.properties.wifi_scanning);
                let heard = reading
                    .and_then(|reading| reading.values.get(&prop::WIFI_SCAN_RESULTS))
                    .cloned();
                if scanning == Some(true) {
                    false
                } else {
                    if let Some(heard) = heard {
                        state.scan = scan_table(heard);
                    }
                    true
                }
            };
            if finished {
                self.publish(worker);
                return MobileManagementOutcome::Done;
            }
        }
        MobileManagementOutcome::Done
    }

    /// What a followed scan answers once its poll was ended: `Skipped`
    /// after firmware update entry, else `Cancelled`.
    fn poll_ended(&self, poll: &Operation) -> Option<MobileManagementOutcome> {
        poll.check().is_err().then(|| {
            if self.state.borrow().entered_dfu {
                MobileManagementOutcome::Skipped
            } else {
                MobileManagementOutcome::Cancelled
            }
        })
    }

    /// Read Wi-Fi again after a network change took, so the list and the
    /// station show it. The change's answer stands unless the read fails.
    async fn refresh_wifi_after(self: &Rc<Self>, worker: &Rc<Worker>) -> Option<Problem> {
        match self
            .refresh_category(worker, UlcpManageCategory::Wifi)
            .await
        {
            MobileManagementOutcome::Failed { problem } => Some(problem),
            _ => None,
        }
    }

    /// Store a network, turn the station on unless it reads on, join the
    /// network now, and save. The save keeps the network and the switch;
    /// which network the device is on is live and never saved. Only the
    /// encoded entry outlives this call's start: the credential is dropped
    /// once it is built.
    pub(super) async fn join_network(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        ssid: Vec<u8>,
        security: u8,
        hidden: bool,
        credential: Vec<u8>,
        offered: Option<u16>,
    ) -> MobileWifiOutcome {
        self.note("stored a Wi-Fi network on a managed device");
        let Ok(item) = ulcp_wifi_network_item(ssid.clone(), security, hidden, true, credential)
        else {
            return MobileWifiOutcome::from_stop(self.refuse_now(worker, Problem::NotBuilt));
        };
        // Off, unread or refused all turn it on.
        let turn_on = self
            .state
            .borrow()
            .reading(UlcpManageCategory::Wifi)
            .and_then(|reading| reading.properties.wifi_enabled)
            != Some(true);
        let engine = self.clone();
        let worker_ = worker.clone();
        let result = self
            .run(worker, true, None, |operation| async move {
                if let Some(refusal) = refusal_of(
                    engine
                        .carrier
                        .network_edit(&worker_, &operation, item, true)
                        .await,
                )? {
                    return Ok(Some(classify_join(
                        MobileWifiStep::Store,
                        refusal,
                        security,
                        offered,
                    )));
                }
                let mut writes = Vec::new();
                if turn_on {
                    writes.push(MobileMeshPropertyWriteRecord {
                        property_id: prop::WIFI_ENABLED,
                        value: vec![1],
                    });
                }
                writes.push(MobileMeshPropertyWriteRecord {
                    property_id: prop::WIFI_NETWORK,
                    value: ssid,
                });
                if let Some((property, refusal)) =
                    engine.write_echoed(&worker_, &operation, writes).await?
                {
                    let step = if property == prop::WIFI_ENABLED {
                        MobileWifiStep::TurnOn
                    } else {
                        MobileWifiStep::Select
                    };
                    return Ok(Some(classify_join(step, refusal, security, offered)));
                }
                engine.carrier.save(&worker_, &operation).await?;
                Ok(None)
            })
            .await;
        self.network_changed(worker, result).await
    }

    /// Replace a network the device knows with the one described. An empty
    /// credential under the stored mode keeps the stored one, which this
    /// phone may never have had.
    pub(super) async fn update_network(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        ssid: Vec<u8>,
        security: u8,
        hidden: bool,
        auto_join: bool,
        credential: Vec<u8>,
    ) -> MobileWifiOutcome {
        self.note("updated a Wi-Fi network stored on a managed device");
        let Ok(item) = ulcp_wifi_network_item(ssid, security, hidden, auto_join, credential) else {
            return MobileWifiOutcome::from_stop(self.refuse_now(worker, Problem::NotBuilt));
        };
        let engine = self.clone();
        let worker_ = worker.clone();
        let result = self
            .run(worker, true, None, |operation| async move {
                if let Some(refusal) = refusal_of(
                    engine
                        .carrier
                        .network_edit(&worker_, &operation, item, true)
                        .await,
                )? {
                    return Ok(Some(classify_update(refusal, security)));
                }
                engine.carrier.save(&worker_, &operation).await?;
                Ok(None)
            })
            .await;
        self.network_changed(worker, result).await
    }

    /// A network change's answer, read again when it took.
    async fn network_changed(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        result: Result<Option<MobileWifiRefusal>, Stop>,
    ) -> MobileWifiOutcome {
        match result {
            Ok(Some(refusal)) => MobileWifiOutcome::Refused { refusal },
            Ok(None) => match self.refresh_wifi_after(worker).await {
                Some(problem) => MobileWifiOutcome::Failed { problem },
                None => MobileWifiOutcome::Done,
            },
            Err(stop) => MobileWifiOutcome::from_stop(stop),
        }
    }

    /// Join a network the device knows, now. Not saved.
    pub(super) async fn join_known_network(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        ssid: Vec<u8>,
    ) -> MobileManagementOutcome {
        self.note("joined a Wi-Fi network stored on a managed device");
        self.button_write(
            worker,
            vec![MobileMeshPropertyWriteRecord {
                property_id: prop::WIFI_NETWORK,
                value: ssid,
            }],
        )
        .await
    }

    /// Leave the current network and join none until told to. Not saved.
    pub(super) async fn disconnect_network(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        self.note("took a managed device off its Wi-Fi network");
        self.button_write(
            worker,
            vec![MobileMeshPropertyWriteRecord {
                property_id: prop::WIFI_NETWORK,
                value: Vec::new(),
            }],
        )
        .await
    }

    /// Let the device choose a known network by itself, or not, and save.
    /// The entry goes with no credential, which keeps the stored one.
    pub(super) async fn set_auto_join(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        ssid: Vec<u8>,
        auto_join: bool,
    ) -> MobileManagementOutcome {
        self.note("changed auto-join for a Wi-Fi network stored on a managed device");
        let stored = self
            .state
            .borrow()
            .reading(UlcpManageCategory::Wifi)
            .and_then(|reading| reading.properties.wifi_networks.as_ref())
            .and_then(|networks| networks.iter().find(|network| network.ssid == ssid))
            .cloned();
        let Some(stored) = stored else {
            return outcome(Err(self.refuse_now(worker, Problem::NotFound)));
        };
        let Ok(item) = ulcp_wifi_network_item(
            stored.ssid,
            stored.security,
            stored.hidden,
            auto_join,
            Vec::new(),
        ) else {
            return outcome(Err(self.refuse_now(worker, Problem::NotBuilt)));
        };
        self.store_network(worker, item, true).await
    }

    /// Forget one network by name, and save.
    pub(super) async fn forget_network(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        ssid: Vec<u8>,
    ) -> MobileManagementOutcome {
        self.note("forgot a Wi-Fi network stored on a managed device");
        self.store_network(worker, ssid, false).await
    }

    /// One network-table edit and a save, then Wi-Fi read again.
    async fn store_network(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
        item: Vec<u8>,
        present: bool,
    ) -> MobileManagementOutcome {
        let engine = self.clone();
        let worker_ = worker.clone();
        let result = outcome(
            self.run(worker, true, None, |operation| async move {
                engine
                    .carrier
                    .network_edit(&worker_, &operation, item, present)
                    .await?;
                engine.carrier.save(&worker_, &operation).await
            })
            .await,
        );
        if result != MobileManagementOutcome::Done {
            return result;
        }
        match self.refresh_wifi_after(worker).await {
            Some(problem) => MobileManagementOutcome::Failed { problem },
            None => MobileManagementOutcome::Done,
        }
    }

    // MARK: Bluetooth

    /// Forget every host paired with the device, and its pairing PIN.
    /// Clearing opens a pairing window, and on a local link drops the very
    /// link the device would say so on, so the reading takes what the
    /// write means: no bonds, pairing open.
    pub(super) async fn clear_bluetooth_pairings(
        self: &Rc<Self>,
        worker: &Rc<Worker>,
    ) -> MobileManagementOutcome {
        self.note("cleared a managed device's Bluetooth pairings");
        let engine = self.clone();
        let worker_ = worker.clone();
        let result = self
            .run(worker, true, None, |operation| async move {
                let answers = engine
                    .carrier
                    .write(&worker_, &operation, clear_bonds_writes())
                    .await?;
                bonds_cleared(&answers).map_err(|failure| Stop::Problem(bonds_problem(failure)))
            })
            .await;
        if result.is_ok() {
            let pushed = |property_id, value| UlcpPropertyPushRecord {
                property_id,
                value,
                kind: UlcpPropertyPushKind::Is,
            };
            self.absorb_pushes(
                worker,
                &[
                    pushed(prop::BLE_BOND_COUNT, vec![0]),
                    pushed(prop::BLE_PAIRING, vec![1]),
                ],
            );
        }
        outcome(result)
    }

    // MARK: Pushes

    /// What the device announced on its own. The device's latest word
    /// wins: pushes do not wait for the queue.
    pub(super) fn absorb_pushes(&self, worker: &Worker, pushes: &[UlcpPropertyPushRecord]) {
        let now = worker.clock.now_ms();
        for push in pushes {
            if push.property_id == prop::WIFI_SCAN_RESULTS {
                self.absorb_scan_result(push);
                continue;
            }
            // An item notice says a table changed, not what it holds.
            if push.kind != UlcpPropertyPushKind::Is {
                continue;
            }
            if push.property_id == prop::ALERT
                && let Ok(alert) = inspect_ulcp_alert(push.value.clone())
            {
                self.state.borrow_mut().alert = alert;
            }
            let values = BTreeMap::from([(push.property_id, push.value.clone())]);
            let affected = self.state.borrow_mut().fold(&values, now);
            // Kept only when a screen holds it: a category never opened
            // reads itself fresh on first sight.
            if affected {
                self.cache(worker, &values);
            }
        }
        self.publish(worker);
    }

    /// Pushes were lost, and any of them could have changed what a
    /// category shows: read every category held again, in turn, each as
    /// its own read. A read already running may have answered before a
    /// lost push, so only one still waiting is not asked again. Stops once
    /// the engine no longer takes commands for the core's owner.
    pub(super) fn resync(self: &Rc<Self>, worker: &Rc<Worker>) {
        let engine = self.clone();
        let worker = worker.clone();
        tokio::task::spawn_local(async move {
            let categories: Vec<UlcpManageCategory> = engine
                .state
                .borrow()
                .readings
                .iter()
                .map(|reading| reading.category)
                .collect();
            for category in categories {
                if !engine.current(worker.owner().as_ref()) {
                    break;
                }
                if !engine.waiting(Read::Category(category)) {
                    engine.refresh_category(&worker, category).await;
                }
            }
        });
    }

    /// Fold one announcement about a scan into the table. `Is` replaces
    /// it whole (an empty one clears it as a scan starts); the others add
    /// or drop one access point.
    fn absorb_scan_result(&self, push: &UlcpPropertyPushRecord) {
        let mut state = self.state.borrow_mut();
        match push.kind {
            UlcpPropertyPushKind::Is => state.scan = scan_table(push.value.clone()),
            UlcpPropertyPushKind::Inserted => {
                if let Ok(result) = inspect_ulcp_wifi_scan_result(push.value.clone()) {
                    state.scan.insert(result.bssid.clone(), result);
                }
            }
            UlcpPropertyPushKind::Removed => {
                if let Ok(result) = inspect_ulcp_wifi_scan_result(push.value.clone()) {
                    state.scan.remove(&result.bssid);
                }
            }
        }
    }
}

/// The clock record that sets a device's clock to the core clock's now.
pub(super) fn clock_now(worker: &Worker) -> UlcpTimeRecord {
    let seconds = worker.clock.now_ms().div_euclid(1000);
    UlcpTimeRecord {
        epoch_seconds: Some(u32::try_from(seconds.max(0)).unwrap_or(u32::MAX)),
    }
}

/// Clearing a device's Bluetooth bonds: its bond count written to zero,
/// the only count a host can write.
pub(super) fn clear_bonds_writes() -> Vec<MobileMeshPropertyWriteRecord> {
    vec![MobileMeshPropertyWriteRecord {
        property_id: prop::BLE_BOND_COUNT,
        value: vec![0],
    }]
}

/// Why a bond clearing did not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BondsNotCleared {
    /// The device's answer said nothing of the bond count.
    Unanswered,
    /// A status, if any, where the count it now holds belonged.
    Refused(Option<u32>),
}

/// What the device answered to [`clear_bonds_writes`]: it echoes the count
/// it now holds, or a status in its place.
pub(super) fn bonds_cleared(
    answers: &[MobileMeshManagementAnswerRecord],
) -> Result<(), BondsNotCleared> {
    let answer = answers.first().ok_or(BondsNotCleared::Unanswered)?;
    if answer.value.is_none() {
        return Err(BondsNotCleared::Refused(answer.status_code));
    }
    Ok(())
}

/// A bond clearing that did not take, as what a screen shows.
pub(super) fn bonds_problem(failure: BondsNotCleared) -> Problem {
    match failure {
        BondsNotCleared::Unanswered => Problem::Unreadable,
        BondsNotCleared::Refused(status) => Problem::Refused {
            refusal: classify(status),
        },
    }
}

/// The scan table a whole value of `PROP_WIFI_SCAN_RESULTS` holds, by
/// BSSID.
fn scan_table(value: Vec<u8>) -> BTreeMap<Vec<u8>, UlcpWifiScanResultRecord> {
    inspect_ulcp_properties(vec![ulcp_property_record(prop::WIFI_SCAN_RESULTS, value)])
        .wifi_scan_results
        .unwrap_or_default()
        .into_iter()
        .map(|result| (result.bssid.clone(), result))
        .collect()
}

/// What a scan heard, strongest first: each named network once, at its
/// strongest access point, and every nameless access point on its own.
fn heard_networks(state: &State) -> Vec<MobileHeardNetworkRecord> {
    let mut by_name: BTreeMap<&[u8], &UlcpWifiScanResultRecord> = BTreeMap::new();
    let mut heard: Vec<&UlcpWifiScanResultRecord> = Vec::new();
    for result in state.scan.values() {
        if result.ssid.is_empty() {
            heard.push(result);
        } else if by_name
            .get(result.ssid.as_slice())
            .is_none_or(|seen| seen.rssi_dbm < result.rssi_dbm)
        {
            by_name.insert(&result.ssid, result);
        }
    }
    heard.extend(by_name.into_values());
    heard.sort_by_key(|result| std::cmp::Reverse(result.rssi_dbm));
    let known = state
        .reading(UlcpManageCategory::Wifi)
        .and_then(|reading| reading.properties.wifi_networks.as_ref());
    heard
        .into_iter()
        .map(|result| MobileHeardNetworkRecord {
            result: result.clone(),
            is_known: known
                .is_some_and(|known| known.iter().any(|network| network.ssid == result.ssid)),
        })
        .collect()
}
