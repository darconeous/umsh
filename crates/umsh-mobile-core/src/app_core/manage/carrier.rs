//! The links a device is managed over, behind one surface. Each exchange
//! runs under the queue entry's operation, which cancels it: a mesh
//! exchange is abandoned in the session, and a local one stops being
//! waited for, which skips it if the driver has not started it yet.

use std::future::Future;
use std::sync::Arc;

use super::operation::Operation;
use umsh_ulcp::ids::prop;

use super::records::MobileKeyTable;
use super::refusal::{Stop, dfu_outcome, driver_problem, mesh_stop, require};
use crate::MobileMeshError;
use crate::app_core::worker::Worker;
use crate::mobile_mesh::{
    MobileMeshManagementAnswerRecord, MobileMeshManagementEventRecord,
    MobileMeshPropertyWriteRecord, MobileMeshResetScope, MobileMeshSession,
};
use crate::radio_driver::{MobileRadioDriver, MobileRadioError};
use crate::ulcp::{
    MobileAnnouncementRecord, UlcpAlertState, UlcpDeviceConfigRecord, UlcpDfuMode,
    UlcpItemMutation, UlcpItemMutationRecord, UlcpSyncRecord, inspect_ulcp_alert,
};

use super::records::MobileManagementProblem as Problem;

#[cfg(test)]
pub(super) use super::tests::script::ScriptedCarrier;

/// What a device is managed through.
pub(super) enum Carrier {
    /// Across the mesh, to the device at `address`.
    Mesh { address: String },
    /// The attached radio, over `driver`, which must still be the core's.
    Companion { driver: Arc<MobileRadioDriver> },
    /// A device native code administers over `driver`, which it owns.
    /// `phone_node_key` is what native code knows this phone's key to be
    /// on that device.
    Administrative {
        driver: Arc<MobileRadioDriver>,
        phone_node_key: Option<Vec<u8>>,
    },
    /// A fake device the engine's tests script.
    #[cfg(test)]
    Scripted(Arc<ScriptedCarrier>),
}

impl Carrier {
    /// Read `property_ids`. Every property asked for is answered,
    /// refusals included.
    pub(super) async fn fetch(
        &self,
        worker: &Worker,
        operation: &Operation,
        property_ids: Vec<u32>,
        multi_hint: bool,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, Stop> {
        if property_ids.is_empty() {
            return Ok(Vec::new());
        }
        let answers = match self {
            Self::Mesh { address } => {
                mesh(worker, operation, |session| {
                    session.begin_management_fetch(address.clone(), property_ids, multi_hint)
                })
                .await?
                .answers
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                self.local(worker, operation, driver.fetch_properties(property_ids))
                    .await?
                    .answers
            }
            #[cfg(test)]
            Self::Scripted(script) => script.fetch(operation, property_ids, multi_hint).await?,
        };
        // A device that answered said something of every property.
        if answers.is_empty() {
            return Err(Stop::Problem(Problem::Unreadable));
        }
        Ok(answers)
    }

    /// Write `writes`, live until a save. Each answer echoes what the
    /// device kept, or holds a status in its place.
    pub(super) async fn write(
        &self,
        worker: &Worker,
        operation: &Operation,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, Stop> {
        match self {
            Self::Mesh { address } => worker
                .write_in_rounds(operation, address, writes)
                .await
                .map_err(mesh_stop),
            Self::Companion { driver } | Self::Administrative { driver, .. } => Ok(self
                .local(worker, operation, driver.write_properties(writes))
                .await?
                .answers),
            #[cfg(test)]
            Self::Scripted(script) => script.write(operation, writes).await,
        }
    }

    /// Keep the device's live configuration across its restarts.
    pub(super) async fn save(&self, worker: &Worker, operation: &Operation) -> Result<(), Stop> {
        let refusal = match self {
            Self::Mesh { address } => {
                mesh(worker, operation, |session| {
                    session.begin_management_save(address.clone())
                })
                .await?
                .refusal
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                self.local(worker, operation, driver.save()).await?.refusal
            }
            #[cfg(test)]
            Self::Scripted(script) => script.save(operation).await?,
        };
        require(refusal)
    }

    /// Start or stop the device's alert. Answers with what the device
    /// reports it is doing when it says so in the answer (the mesh); a
    /// local link reports it by push instead.
    pub(super) async fn set_alert(
        &self,
        worker: &Worker,
        operation: &Operation,
        state: UlcpAlertState,
    ) -> Result<Option<UlcpAlertState>, Stop> {
        match self {
            Self::Mesh { address } => {
                let event = mesh(worker, operation, |session| {
                    session.begin_management_set_alert(address.clone(), state)
                })
                .await?;
                let Some(answer) = event.answers.first() else {
                    require(event.refusal)?;
                    return Err(Stop::Problem(Problem::Unreadable));
                };
                require(answer.refusal)?;
                answer
                    .value
                    .clone()
                    .and_then(|value| inspect_ulcp_alert(value).ok())
                    .map(Some)
                    .ok_or(Stop::Problem(Problem::Unreadable))
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                self.local(worker, operation, driver.set_alert(state))
                    .await?;
                Ok(None)
            }
            #[cfg(test)]
            Self::Scripted(script) => script.set_alert(operation, state).await,
        }
    }

    /// Restart or wipe the device. A local link offers only those two.
    pub(super) async fn reset(
        &self,
        worker: &Worker,
        operation: &Operation,
        scope: MobileMeshResetScope,
    ) -> Result<(), Stop> {
        match self {
            Self::Mesh { address } => {
                let event = mesh(worker, operation, |session| {
                    session.begin_management_reset(address.clone(), scope)
                })
                .await?;
                require(event.refusal)
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => match scope {
                MobileMeshResetScope::Reboot => {
                    self.local(worker, operation, driver.reboot()).await
                }
                MobileMeshResetScope::Factory => {
                    self.local(worker, operation, driver.factory_reset()).await
                }
                MobileMeshResetScope::Protocol | MobileMeshResetScope::Restore => {
                    Err(Stop::Problem(Problem::NotBuilt))
                }
            },
            #[cfg(test)]
            Self::Scripted(script) => script.reset(operation, scope).await,
        }
    }

    /// Put the device into firmware update, confirmed by its status
    /// (`dfu_outcome`). A device on its way into its bootloader may not
    /// answer, so a lost answer is unconfirmed rather than a failure.
    pub(super) async fn enter_dfu(
        &self,
        worker: &Worker,
        operation: &Operation,
        mode: UlcpDfuMode,
    ) -> Result<(), Stop> {
        let status = match self {
            Self::Mesh { address } => dfu_status(
                mesh(worker, operation, |session| {
                    session.begin_management_dfu(address.clone(), mode)
                })
                .await
                .map(|event| event.status_code),
            )?,
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                self.bound(worker)?;
                match self.local(worker, operation, driver.enter_dfu(mode)).await {
                    Ok(event) => event.status_code,
                    Err(Stop::Cancelled) => return Err(Stop::Cancelled),
                    Err(_) => None,
                }
            }
            #[cfg(test)]
            Self::Scripted(script) => dfu_status(script.enter_dfu(operation, mode).await)?,
        };
        dfu_outcome(status).map_err(mesh_stop)
    }

    /// Ask the device to announce itself now.
    pub(super) async fn announce(
        &self,
        worker: &Worker,
        operation: &Operation,
        request: MobileAnnouncementRecord,
    ) -> Result<(), Stop> {
        let refusal = match self {
            Self::Mesh { address } => {
                mesh(worker, operation, |session| {
                    session.begin_management_announce(address.clone(), request)
                })
                .await?
                .refusal
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                self.local(worker, operation, driver.announce(request))
                    .await?
                    .refusal
            }
            #[cfg(test)]
            Self::Scripted(script) => script.announce(operation, request).await?,
        };
        require(refusal)
    }

    /// Put `key` into one of the device's key tables, or take it out. A
    /// local link's session saves behind each edit; across the mesh the
    /// edit is live until a save.
    pub(super) async fn table_edit(
        &self,
        worker: &Worker,
        operation: &Operation,
        table: MobileKeyTable,
        key: Vec<u8>,
        present: bool,
    ) -> Result<(), Stop> {
        match self {
            Self::Mesh { address } => {
                let event = mesh(worker, operation, |session| {
                    let address = address.clone();
                    match (table, present) {
                        (MobileKeyTable::Administrators, true) => {
                            session.begin_management_insert_admin(address, key)
                        }
                        (MobileKeyTable::Administrators, false) => {
                            session.begin_management_remove_admin(address, key)
                        }
                        (MobileKeyTable::Peers, true) => {
                            session.begin_management_insert_peer(address, key)
                        }
                        (MobileKeyTable::Peers, false) => {
                            session.begin_management_remove_peer(address, key)
                        }
                    }
                })
                .await?;
                require_table_edit(&event.answers, event.refusal)
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                let call = async {
                    match (table, present) {
                        (MobileKeyTable::Administrators, true) => {
                            driver.insert_device_admin(key).await
                        }
                        (MobileKeyTable::Administrators, false) => {
                            driver.remove_device_admin(key).await
                        }
                        (MobileKeyTable::Peers, true) => driver.insert_device_peer(key).await,
                        (MobileKeyTable::Peers, false) => driver.remove_device_peer(key).await,
                    }
                };
                self.local(worker, operation, call).await
            }
            #[cfg(test)]
            Self::Scripted(script) => script.table_edit(operation, table, key, present).await,
        }
    }

    /// Write a whole device configuration and have the device save it, as
    /// one pass the link's session runs: a cancel stops waiting for it,
    /// not the pass. Only a device administered in hand takes one.
    ///
    /// What `unreadable` names is left out even once the device answers
    /// it: the configuration holds placeholders there, planned against
    /// the read that could not.
    pub(super) async fn configure_device(
        &self,
        worker: &Worker,
        operation: &Operation,
        configuration: UlcpDeviceConfigRecord,
        unreadable: Vec<u32>,
    ) -> Result<(), Stop> {
        match self {
            Self::Mesh { .. } | Self::Companion { .. } => Err(Stop::Problem(Problem::NotBuilt)),
            Self::Administrative { driver, .. } => {
                let call = driver.core_configure_device(configuration, unreadable);
                self.local(worker, operation, call).await
            }
            #[cfg(test)]
            Self::Scripted(script) => {
                script
                    .configure_device(operation, configuration, &unreadable)
                    .await
            }
        }
    }

    /// Read the whole device again, as an attach reads it. A device that
    /// answers with no configuration is unreadable.
    pub(super) async fn read_back(
        &self,
        worker: &Worker,
        operation: &Operation,
    ) -> Result<UlcpSyncRecord, Stop> {
        let reported = match self {
            Self::Mesh { .. } | Self::Companion { .. } => {
                return Err(Stop::Problem(Problem::NotBuilt));
            }
            Self::Administrative { driver, .. } => {
                self.local(worker, operation, driver.refresh())
                    .await?
                    .provisioning
            }
            #[cfg(test)]
            Self::Scripted(script) => script.read_back(operation).await?,
        };
        reported.ok_or(Stop::Problem(Problem::Unreadable))
    }

    /// Whether the link's session saves behind each key-table edit, so
    /// none follows them.
    pub(super) fn saves_table_edits(&self) -> bool {
        match self {
            Self::Mesh { .. } => false,
            Self::Companion { .. } | Self::Administrative { .. } => true,
            #[cfg(test)]
            Self::Scripted(script) => script.saves_table_edits,
        }
    }

    /// Store a Wi-Fi network (`item`, a whole entry), or forget one
    /// (`item`, its SSID). Live until a save.
    pub(super) async fn network_edit(
        &self,
        worker: &Worker,
        operation: &Operation,
        item: Vec<u8>,
        present: bool,
    ) -> Result<(), Stop> {
        match self {
            Self::Mesh { address } => {
                let event = mesh(worker, operation, |session| {
                    if present {
                        session.begin_management_insert(address.clone(), prop::WIFI_NETWORKS, item)
                    } else {
                        session.begin_management_remove(address.clone(), prop::WIFI_NETWORKS, item)
                    }
                })
                .await?;
                require_table_edit(&event.answers, event.refusal)
            }
            Self::Companion { driver } | Self::Administrative { driver, .. } => {
                let mutation = UlcpItemMutationRecord {
                    mutation: if present {
                        UlcpItemMutation::Insert
                    } else {
                        UlcpItemMutation::Remove
                    },
                    value: item,
                };
                let event = self
                    .local(
                        worker,
                        operation,
                        driver.edit_property_items(prop::WIFI_NETWORKS, vec![mutation]),
                    )
                    .await?;
                require_table_edit(&event.answers, event.refusal)
            }
            #[cfg(test)]
            Self::Scripted(script) => script.network_edit(operation, item, present).await,
        }
    }

    /// This phone's node key as the device would hold it, when known.
    pub(super) fn phone_node_key(&self, worker: &Worker) -> Option<Vec<u8>> {
        match self {
            Self::Mesh { .. } | Self::Companion { .. } => worker
                .owner()
                .and_then(|owner| crate::public_identity_bytes(owner).ok()),
            Self::Administrative { phone_node_key, .. } => phone_node_key.clone(),
            #[cfg(test)]
            Self::Scripted(script) => script.phone_node_key.clone(),
        }
    }

    /// The core's radio this carrier sends through, when it is the
    /// companion link.
    pub(super) fn driver(&self) -> Option<&Arc<MobileRadioDriver>> {
        match self {
            Self::Companion { driver } => Some(driver),
            Self::Mesh { .. } | Self::Administrative { .. } => None,
            #[cfg(test)]
            Self::Scripted(_) => None,
        }
    }
}

/// A firmware-update entry's status over the mesh: an exchange that got
/// no readable answer has no status, which is unconfirmed, not a failure.
fn dfu_status(answer: Result<Option<u32>, Stop>) -> Result<Option<u32>, Stop> {
    match answer {
        Err(Stop::Problem(Problem::NoAnswer | Problem::Unreachable | Problem::Unreadable)) => {
            Ok(None)
        }
        answer => answer,
    }
}

/// A one-entry table edit answers with the table as it now stands, or with
/// a status where that belonged.
fn require_table_edit(
    answers: &[MobileMeshManagementAnswerRecord],
    refusal: Option<u32>,
) -> Result<(), Stop> {
    require(
        answers
            .first()
            .and_then(|answer| answer.refusal)
            .or(refusal),
    )
}

/// One mesh exchange, as the screens see its failures.
async fn mesh(
    worker: &Worker,
    operation: &Operation,
    begin: impl FnOnce(&MobileMeshSession) -> Result<u64, MobileMeshError>,
) -> Result<MobileMeshManagementEventRecord, Stop> {
    worker.exchange(operation, begin).await.map_err(mesh_stop)
}

impl Carrier {
    /// Whether the companion's driver is still the core's: a radio switch
    /// never sends one radio's edits to another. An administrative driver
    /// is native code's, and no switch of the core's radio touches it.
    fn bound(&self, worker: &Worker) -> Result<(), Stop> {
        let Self::Companion { driver } = self else {
            return Ok(());
        };
        if worker
            .driver()
            .is_some_and(|current| Arc::ptr_eq(&current, driver))
        {
            Ok(())
        } else {
            Err(Stop::Problem(Problem::NoRadio))
        }
    }

    /// One local exchange, ended by its answer or by a cancel, which drops
    /// the call and so lets the driver skip it if it has not begun.
    async fn local<T>(
        &self,
        worker: &Worker,
        operation: &Operation,
        call: impl Future<Output = Result<T, MobileRadioError>>,
    ) -> Result<T, Stop> {
        if operation.check().is_err() {
            return Err(Stop::Cancelled);
        }
        self.bound(worker)?;
        tokio::select! {
            biased;
            result = call => result.map_err(|error| Stop::Problem(driver_problem(error))),
            () = operation.wait_cancelled() => Err(Stop::Cancelled),
        }
    }
}
