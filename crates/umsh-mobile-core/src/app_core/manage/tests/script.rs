//! A fake device the engine's tests script: it holds property values,
//! answers reads from them, takes writes into them, and records every
//! exchange it was asked for. A test can refuse a property, fail the next
//! exchanges, or hold every exchange until it lets one through.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Semaphore;
use umsh_ulcp::ids::prop;
use umsh_ulcp::{Cmd, Status};

use super::super::operation::Operation;
use super::super::records::{MobileKeyTable, MobileManagementProblem};
use super::super::refusal::{Stop, refused};
use crate::mobile_mesh::{
    MobileMeshManagementAnswerRecord, MobileMeshPropertyWriteRecord, MobileMeshResetScope,
};
use crate::ulcp::{
    MobileAnnouncementRecord, UlcpAlertState, UlcpDeviceConfigRecord, UlcpDfuMode,
    UlcpPropertyFrameRecord, UlcpSyncRecord, device_config_writes, inspect_ulcp_sync,
};

/// This phone's key, as a scripted device knows it.
pub(in crate::app_core::manage) const PHONE_NODE_KEY: [u8; 32] = [7; 32];

/// One exchange the device was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::app_core::manage) enum Call {
    Fetch {
        property_ids: Vec<u32>,
        multi_hint: bool,
    },
    Write(Vec<(u32, Vec<u8>)>),
    Save,
    SetAlert(UlcpAlertState),
    Reset(MobileMeshResetScope),
    EnterDfu(UlcpDfuMode),
    Announce(MobileAnnouncementRecord),
    TableEdit {
        table: MobileKeyTable,
        key: Vec<u8>,
        present: bool,
    },
    NetworkEdit {
        item: Vec<u8>,
        present: bool,
    },
    /// A whole configuration pass: the writes it made, in order.
    Configure(Vec<(u32, Vec<u8>)>),
    /// A whole read, as an attach makes one.
    ReadBack,
}

#[derive(Default)]
struct Device {
    values: BTreeMap<u32, Vec<u8>>,
    /// Properties a read or a write is refused, with the status in the
    /// value's place.
    refusing: BTreeMap<u32, Option<u32>>,
    /// Properties a read leaves out of its answer.
    omitted: BTreeSet<u32>,
    /// What the next exchanges fail with, in order.
    failures: VecDeque<Stop>,
    asked: Vec<Call>,
    save_refusal: Option<u32>,
    dfu_status: Option<u32>,
    /// The device echoes the alert it holds, as over the mesh.
    alert_echo: bool,
    /// What the next table edits are refused with, in order.
    edit_refusals: VecDeque<u32>,
    /// What a configuration pass leaves in place of what it wrote: a
    /// clamp, or a misreport.
    rewrites: BTreeMap<u32, Vec<u8>>,
    /// What the next whole read fails with.
    read_back_failure: Option<Stop>,
    /// A whole read answers with no configuration.
    read_back_empty: bool,
}

pub(in crate::app_core::manage) struct ScriptedCarrier {
    /// What the device's cache is kept under, if anything.
    pub(in crate::app_core::manage) address: Option<String>,
    pub(in crate::app_core::manage) phone_node_key: Option<Vec<u8>>,
    /// The link saves behind each key-table edit, as a local one does.
    pub(in crate::app_core::manage) saves_table_edits: bool,
    device: Mutex<Device>,
    hold: Mutex<Option<Arc<Semaphore>>>,
}

impl ScriptedCarrier {
    pub(in crate::app_core::manage) fn new(
        address: Option<String>,
        values: BTreeMap<u32, Vec<u8>>,
    ) -> Arc<Self> {
        Self::configured(address, values, Some(PHONE_NODE_KEY.to_vec()), false)
    }

    /// A device whose link saves behind each key-table edit, as a local
    /// one does, and that knows this phone as `phone_node_key`.
    pub(in crate::app_core::manage) fn configured(
        address: Option<String>,
        values: BTreeMap<u32, Vec<u8>>,
        phone_node_key: Option<Vec<u8>>,
        saves_table_edits: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            address,
            phone_node_key,
            saves_table_edits,
            device: Mutex::new(Device {
                values,
                ..Device::default()
            }),
            hold: Mutex::new(None),
        })
    }

    fn device(&self) -> MutexGuard<'_, Device> {
        self.device.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(in crate::app_core::manage) fn set(&self, property: u32, value: Vec<u8>) {
        self.device().values.insert(property, value);
    }

    pub(in crate::app_core::manage) fn value(&self, property: u32) -> Option<Vec<u8>> {
        self.device().values.get(&property).cloned()
    }

    pub(in crate::app_core::manage) fn refuse(&self, property: u32, status: Option<u32>) {
        self.device().refusing.insert(property, status);
    }

    /// Answer `property` again.
    pub(in crate::app_core::manage) fn unrefuse(&self, property: u32) {
        self.device().refusing.remove(&property);
    }

    pub(in crate::app_core::manage) fn omit(&self, property: u32) {
        self.device().omitted.insert(property);
    }

    pub(in crate::app_core::manage) fn fail_next(&self, stop: Stop) {
        self.device().failures.push_back(stop);
    }

    pub(in crate::app_core::manage) fn refuse_save(&self, status: Option<u32>) {
        self.device().save_refusal = status;
    }

    pub(in crate::app_core::manage) fn answer_dfu(&self, status: Option<u32>) {
        self.device().dfu_status = status;
    }

    /// Refuse the next table edit with `status`.
    pub(in crate::app_core::manage) fn refuse_edit(&self, status: u32) {
        self.device().edit_refusals.push_back(status);
    }

    /// After each configuration pass, hold `value` for `property`
    /// whatever was written.
    pub(in crate::app_core::manage) fn rewrite_on_configure(&self, property: u32, value: Vec<u8>) {
        self.device().rewrites.insert(property, value);
    }

    /// Fail the next whole read with `stop`.
    pub(in crate::app_core::manage) fn fail_read_back(&self, stop: Stop) {
        self.device().read_back_failure = Some(stop);
    }

    /// Answer whole reads with no configuration.
    pub(in crate::app_core::manage) fn answer_read_back_empty(&self) {
        self.device().read_back_empty = true;
    }

    /// The device as a whole read reports it: every value it answers,
    /// reduced as a session reduces an attach's answers. `PROP_CAPS` must
    /// be among them.
    pub(in crate::app_core::manage) fn sync(&self) -> Option<UlcpSyncRecord> {
        let device = self.device();
        let frames = device
            .values
            .iter()
            .filter(|(property, _)| {
                !device.refusing.contains_key(property) && !device.omitted.contains(property)
            })
            .map(|(property, value)| UlcpPropertyFrameRecord {
                transaction_id: 1,
                command: Cmd::PropIs as u8,
                property_id: *property,
                value: value.clone(),
            })
            .collect();
        drop(device);
        inspect_ulcp_sync(frames).ok()
    }

    pub(in crate::app_core::manage) fn echo_alert(&self) {
        self.device().alert_echo = true;
    }

    pub(in crate::app_core::manage) fn asked(&self) -> Vec<Call> {
        self.device().asked.clone()
    }

    pub(in crate::app_core::manage) fn clear_asked(&self) {
        self.device().asked.clear();
    }

    /// Hold every exchange from now on until `release` lets one through.
    pub(in crate::app_core::manage) fn hold(&self) {
        *self.hold.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Arc::new(Semaphore::new(0)));
    }

    /// Let one held exchange through, and keep holding the rest.
    pub(in crate::app_core::manage) fn pass_one(&self) {
        if let Some(gate) = self
            .hold
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            gate.add_permits(1);
        }
    }

    /// Stop holding, and let everything held through.
    pub(in crate::app_core::manage) fn unhold(&self) {
        if let Some(gate) = self
            .hold
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            gate.add_permits(Semaphore::MAX_PERMITS / 2);
        }
    }

    /// Record `call`, wait for the hold, and take the next failure.
    async fn exchange(&self, operation: &Operation, call: Call) -> Result<(), Stop> {
        if operation.check().is_err() {
            return Err(Stop::Cancelled);
        }
        self.device().asked.push(call);
        let gate = self
            .hold
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(gate) = gate {
            tokio::select! {
                biased;
                permit = gate.acquire() => {
                    if let Ok(permit) = permit {
                        permit.forget();
                    }
                }
                () = operation.wait_cancelled() => return Err(Stop::Cancelled),
            }
        }
        match self.device().failures.pop_front() {
            Some(stop) => Err(stop),
            None => Ok(()),
        }
    }

    pub(in crate::app_core::manage) async fn fetch(
        &self,
        operation: &Operation,
        property_ids: Vec<u32>,
        multi_hint: bool,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, Stop> {
        self.exchange(
            operation,
            Call::Fetch {
                property_ids: property_ids.clone(),
                multi_hint,
            },
        )
        .await?;
        let device = self.device();
        Ok(property_ids
            .into_iter()
            .filter(|property| !device.omitted.contains(property))
            .map(|property| {
                if let Some(status) = device.refusing.get(&property) {
                    return refusal(property, *status);
                }
                match device.values.get(&property) {
                    Some(value) => answer(property, value.clone()),
                    None => refusal(property, Some(Status::PROP_NOT_FOUND.0)),
                }
            })
            .collect())
    }

    pub(in crate::app_core::manage) async fn write(
        &self,
        operation: &Operation,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, Stop> {
        self.exchange(
            operation,
            Call::Write(
                writes
                    .iter()
                    .map(|write| (write.property_id, write.value.clone()))
                    .collect(),
            ),
        )
        .await?;
        let mut device = self.device();
        Ok(writes
            .into_iter()
            .map(|write| {
                if let Some(status) = device.refusing.get(&write.property_id) {
                    return refusal(write.property_id, *status);
                }
                device.values.insert(write.property_id, write.value.clone());
                answer(write.property_id, write.value)
            })
            .collect())
    }

    pub(in crate::app_core::manage) async fn save(
        &self,
        operation: &Operation,
    ) -> Result<Option<u32>, Stop> {
        self.exchange(operation, Call::Save).await?;
        Ok(self.device().save_refusal)
    }

    pub(in crate::app_core::manage) async fn set_alert(
        &self,
        operation: &Operation,
        state: UlcpAlertState,
    ) -> Result<Option<UlcpAlertState>, Stop> {
        self.exchange(operation, Call::SetAlert(state)).await?;
        Ok(self.device().alert_echo.then_some(state))
    }

    pub(in crate::app_core::manage) async fn reset(
        &self,
        operation: &Operation,
        scope: MobileMeshResetScope,
    ) -> Result<(), Stop> {
        self.exchange(operation, Call::Reset(scope)).await
    }

    pub(in crate::app_core::manage) async fn enter_dfu(
        &self,
        operation: &Operation,
        mode: UlcpDfuMode,
    ) -> Result<Option<u32>, Stop> {
        self.exchange(operation, Call::EnterDfu(mode)).await?;
        Ok(self.device().dfu_status)
    }

    pub(in crate::app_core::manage) async fn announce(
        &self,
        operation: &Operation,
        request: MobileAnnouncementRecord,
    ) -> Result<Option<u32>, Stop> {
        self.exchange(operation, Call::Announce(request)).await?;
        Ok(None)
    }
}

impl ScriptedCarrier {
    /// A key table is its keys end to end; an edit puts one in or takes
    /// it out.
    pub(in crate::app_core::manage) async fn table_edit(
        &self,
        operation: &Operation,
        table: MobileKeyTable,
        key: Vec<u8>,
        present: bool,
    ) -> Result<(), Stop> {
        self.exchange(
            operation,
            Call::TableEdit {
                table,
                key: key.clone(),
                present,
            },
        )
        .await?;
        let mut device = self.device();
        if let Some(status) = device.edit_refusals.pop_front() {
            return Err(Stop::Problem(refused(status)));
        }
        let property = match table {
            MobileKeyTable::Peers => prop::DEV_PEERS,
            MobileKeyTable::Administrators => prop::DEV_ADMINS,
        };
        let held = device.values.remove(&property).unwrap_or_default();
        let mut keys: Vec<Vec<u8>> = held
            .chunks(32)
            .map(<[u8]>::to_vec)
            .filter(|held| *held != key)
            .collect();
        if present {
            keys.push(key);
        }
        device.values.insert(property, keys.concat());
        Ok(())
    }

    /// The writes `configuration` makes against what the device reports,
    /// leaving out `unreadable` as well, taken in order; then the
    /// rewrites.
    pub(in crate::app_core::manage) async fn configure_device(
        &self,
        operation: &Operation,
        configuration: UlcpDeviceConfigRecord,
        unreadable: &[u32],
    ) -> Result<(), Stop> {
        let mut reported = self
            .sync()
            .ok_or(Stop::Problem(MobileManagementProblem::Unreadable))?;
        reported.unreadable_properties.extend_from_slice(unreadable);
        let writes = device_config_writes(configuration, &reported)
            .map_err(|_| Stop::Problem(MobileManagementProblem::NotBuilt))?;
        self.exchange(operation, Call::Configure(writes.clone()))
            .await?;
        let mut device = self.device();
        device.values.extend(writes);
        let rewrites = device.rewrites.clone();
        device.values.extend(rewrites);
        Ok(())
    }

    pub(in crate::app_core::manage) async fn read_back(
        &self,
        operation: &Operation,
    ) -> Result<Option<UlcpSyncRecord>, Stop> {
        self.exchange(operation, Call::ReadBack).await?;
        let (failure, empty) = {
            let mut device = self.device();
            (device.read_back_failure.take(), device.read_back_empty)
        };
        if let Some(stop) = failure {
            return Err(stop);
        }
        Ok(if empty { None } else { self.sync() })
    }

    pub(in crate::app_core::manage) async fn network_edit(
        &self,
        operation: &Operation,
        item: Vec<u8>,
        present: bool,
    ) -> Result<(), Stop> {
        self.exchange(operation, Call::NetworkEdit { item, present })
            .await?;
        match self.device().edit_refusals.pop_front() {
            Some(status) => Err(Stop::Problem(refused(status))),
            None => Ok(()),
        }
    }
}

fn answer(property_id: u32, value: Vec<u8>) -> MobileMeshManagementAnswerRecord {
    MobileMeshManagementAnswerRecord {
        property_id,
        value: Some(value),
        status_code: None,
        refusal: None,
    }
}

fn refusal(property_id: u32, status: Option<u32>) -> MobileMeshManagementAnswerRecord {
    MobileMeshManagementAnswerRecord {
        property_id,
        value: None,
        status_code: status,
        refusal: status,
    }
}
