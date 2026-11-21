//! Managing a device across the mesh. Each command runs under a
//! [`MobileOperation`] native code made for it, which cancels it and names
//! its progress in the changes.
//!
//! An operation is single-use, since a cancel must reach one command and
//! not a later one that reused it. A command made of several exchanges (a
//! write that needs more than one round) runs them all under its one
//! operation, cancelling whichever is current.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::watch;

use super::policy::MANAGEMENT_BACKSTOP_MS;
use super::routes::checked_address;
use super::worker::Worker;
use super::{MobileAppCore, MobileAppError, mesh_error};
use crate::MobileMeshError;
use crate::mobile_mesh::{
    MobileMeshManagementAnswerRecord, MobileMeshManagementEventRecord, MobileMeshManagementOutcome,
    MobileMeshPropertyWriteRecord, MobileMeshResetScope, MobileMeshSession,
};
use crate::ulcp::{
    MobileAnnouncementRecord, UlcpAlertState, UlcpDfuMode, inspect_ulcp_alert,
    ulcp_managed_property_ids,
};

/// Operation IDs, unique for the process.
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);

/// One remote management command, which native code can cancel.
#[derive(uniffi::Object)]
pub struct MobileOperation {
    id: u64,
    used: std::sync::atomic::AtomicBool,
    cancelled: watch::Sender<bool>,
}

#[uniffi::export]
impl MobileOperation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_OPERATION.fetch_add(1, Ordering::Relaxed),
            used: std::sync::atomic::AtomicBool::new(false),
            cancelled: watch::Sender::new(false),
        })
    }

    /// What its progress is reported under.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Stop the command: one not yet sent never is, and one on the air
    /// fails with `Cancelled` at once. The device may still act on what it
    /// already has.
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }
}

impl MobileOperation {
    /// Take it for one command.
    fn claim(&self) -> Result<(), MobileAppError> {
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(MobileAppError::OperationReused);
        }
        self.check()
    }

    fn check(&self) -> Result<(), MobileAppError> {
        if *self.cancelled.borrow() {
            return Err(MobileAppError::Cancelled);
        }
        Ok(())
    }

    async fn wait_cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        let _ = cancelled.wait_for(|cancelled| *cancelled).await;
    }
}

/// The device's refusal, if it refused.
fn require(refusal: Option<u32>) -> Result<(), MobileAppError> {
    refusal.map_or(Ok(()), |status| Err(MobileAppError::Refused { status }))
}

/// A one-entry table edit answers with the list as it now stands, or with a
/// status where that list belonged.
fn require_table_edit(event: &MobileMeshManagementEventRecord) -> Result<(), MobileAppError> {
    require(
        event
            .answers
            .first()
            .and_then(|answer| answer.refusal)
            .or(event.refusal),
    )
}

/// A request the session would not begin is the caller's, never the
/// radio's.
fn begin_error(error: MobileMeshError) -> MobileAppError {
    match error {
        MobileMeshError::InvalidPeer
        | MobileMeshError::InvalidRequest
        | MobileMeshError::InvalidRoute => MobileAppError::InvalidRequest,
        error => mesh_error(error),
    }
}

impl Worker {
    /// One exchange under `operation`, ended by its answer.
    async fn exchange(
        &self,
        operation: &MobileOperation,
        begin: impl FnOnce(&MobileMeshSession) -> Result<u64, MobileMeshError>,
    ) -> Result<MobileMeshManagementEventRecord, MobileAppError> {
        operation.check()?;
        let session = self.radio_session()?;
        let id = begin(&session).map_err(begin_error)?;
        let deadline = self.clock.monotonic_ms() + MANAGEMENT_BACKSTOP_MS;
        // Biased, so the waiter is registered before a cancel is seen;
        // either way a cancel reaches the session.
        let event = tokio::select! {
            biased;
            event = self.await_management(id, Some(operation.id), deadline) => event?,
            () = operation.wait_cancelled() => {
                self.abandon_management(id);
                return Err(MobileAppError::Cancelled);
            }
        };
        match event.outcome {
            MobileMeshManagementOutcome::Replied | MobileMeshManagementOutcome::Acknowledged => {
                Ok(event)
            }
            MobileMeshManagementOutcome::TimedOut => Err(MobileAppError::NoAnswer),
            MobileMeshManagementOutcome::Unreachable => Err(MobileAppError::Unreachable),
            MobileMeshManagementOutcome::Canceled => Err(MobileAppError::Cancelled),
            MobileMeshManagementOutcome::Failed | MobileMeshManagementOutcome::Progress => {
                Err(MobileAppError::Unreadable)
            }
        }
    }

    async fn remote_write(
        &self,
        operation: &MobileOperation,
        address: &str,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, MobileAppError> {
        let mut remaining = writes;
        let mut answers = Vec::new();
        while !remaining.is_empty() {
            let batch = remaining.clone();
            let event = self
                .exchange(operation, |session| {
                    session.begin_management_set_many(address.to_owned(), batch)
                })
                .await?;
            // A device stops before an answer that would not fit, so a short
            // one is ordinary; an empty one says the first write alone would
            // not fit, and asking again would loop.
            if event.answers.is_empty() {
                return Err(MobileAppError::Unreadable);
            }
            remaining.drain(..event.answers.len().min(remaining.len()));
            answers.extend(event.answers);
        }
        Ok(answers)
    }
}

#[uniffi::export]
impl MobileAppCore {
    /// Read properties from a device. Every property asked for is
    /// answered, refusals included.
    pub async fn remote_fetch(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        property_ids: Vec<u32>,
        multi_hint: bool,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            if property_ids.is_empty() {
                return Ok(Vec::new());
            }
            let event = worker
                .exchange(&operation, |session| {
                    session.begin_management_fetch(address, property_ids, multi_hint)
                })
                .await?;
            // A device that answered said something of every property.
            if event.answers.is_empty() {
                return Err(MobileAppError::Unreadable);
            }
            Ok(event.answers)
        })
        .await
    }

    /// Write properties on a device, live until a save, in as many rounds
    /// as its answers need. Each answer echoes what the device kept.
    pub async fn remote_write(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        writes: Vec<MobileMeshPropertyWriteRecord>,
    ) -> Result<Vec<MobileMeshManagementAnswerRecord>, MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            worker.remote_write(&operation, &address, writes).await
        })
        .await
    }

    /// Keep a device's live configuration across its restarts.
    pub async fn remote_save(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| session.begin_management_save(address))
                .await?;
            require(event.refusal)
        })
        .await
    }

    /// Add a node to a device's administrators, or take it out.
    pub async fn remote_set_admin(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        public_key: Vec<u8>,
        present: bool,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    if present {
                        session.begin_management_insert_admin(address, public_key)
                    } else {
                        session.begin_management_remove_admin(address, public_key)
                    }
                })
                .await?;
            require_table_edit(&event)
        })
        .await
    }

    /// Add a peer key to a device's identity, or take it out.
    pub async fn remote_set_peer(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        public_key: Vec<u8>,
        present: bool,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    if present {
                        session.begin_management_insert_peer(address, public_key)
                    } else {
                        session.begin_management_remove_peer(address, public_key)
                    }
                })
                .await?;
            require_table_edit(&event)
        })
        .await
    }

    /// Add a Wi-Fi network to a device, or take one out by `item`.
    pub async fn remote_set_wifi_network(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        item: Vec<u8>,
        present: bool,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        let property = ulcp_managed_property_ids().wifi_networks;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    if present {
                        session.begin_management_insert(address, property, item)
                    } else {
                        session.begin_management_remove(address, property, item)
                    }
                })
                .await?;
            require_table_edit(&event)
        })
        .await
    }

    /// Start or stop a device's alert. Answers with what the device
    /// reports it is doing now.
    pub async fn remote_set_alert(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        state: UlcpAlertState,
    ) -> Result<UlcpAlertState, MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    session.begin_management_set_alert(address, state)
                })
                .await?;
            let Some(answer) = event.answers.first() else {
                require(event.refusal)?;
                return Err(MobileAppError::Unreadable);
            };
            require(answer.refusal)?;
            answer
                .value
                .clone()
                .and_then(|value| inspect_ulcp_alert(value).ok())
                .ok_or(MobileAppError::Unreadable)
        })
        .await
    }

    /// Restart or wipe a device.
    pub async fn remote_reset(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        scope: MobileMeshResetScope,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    session.begin_management_reset(address, scope)
                })
                .await?;
            require(event.refusal)
        })
        .await
    }

    /// Put a device into firmware update, confirmed by its status.
    pub async fn remote_enter_dfu(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        mode: UlcpDfuMode,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    session.begin_management_dfu(address, mode)
                })
                .await;
            match event {
                Ok(event) => match event.status_code {
                    Some(0) => Ok(()),
                    Some(2 | 5) => Err(MobileAppError::DfuUnsupported),
                    Some(status) => Err(MobileAppError::DfuRefused { status }),
                    None => Err(MobileAppError::DfuUnconfirmed),
                },
                // A device on its way into its bootloader may not answer.
                Err(
                    MobileAppError::NoAnswer
                    | MobileAppError::Unreachable
                    | MobileAppError::Unreadable,
                ) => Err(MobileAppError::DfuUnconfirmed),
                Err(error) => Err(error),
            }
        })
        .await
    }

    /// Ask a device to announce itself now.
    pub async fn remote_announce(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
        request: MobileAnnouncementRecord,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        self.command(move |worker| async move {
            let event = worker
                .exchange(&operation, |session| {
                    session.begin_management_announce(address, request)
                })
                .await?;
            require(event.refusal)
        })
        .await
    }

    /// Make a device forget every Bluetooth host it was bonded with.
    pub async fn remote_clear_bonds(
        &self,
        operation: Arc<MobileOperation>,
        address: String,
    ) -> Result<(), MobileAppError> {
        operation.claim()?;
        checked_address(&address)?;
        let property = ulcp_managed_property_ids().ble_bond_count;
        self.command(move |worker| async move {
            // The bond count written to zero; the device echoes the count it
            // now holds, or a status in its place.
            let answers = worker
                .remote_write(
                    &operation,
                    &address,
                    vec![MobileMeshPropertyWriteRecord {
                        property_id: property,
                        value: vec![0],
                    }],
                )
                .await?;
            let answer = answers.first().ok_or(MobileAppError::Unreadable)?;
            if answer.value.is_none() {
                return Err(MobileAppError::Refused {
                    status: answer.status_code.unwrap_or(0),
                });
            }
            Ok(())
        })
        .await
    }
}
