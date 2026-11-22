//! What one queue entry runs under: an [`Operation`], which cancels it,
//! and the mesh exchange that runs under one.
//!
//! An entry made of several exchanges (a write that needs more than one
//! round) runs them all under its one operation, cancelling whichever is
//! current.

use tokio::sync::watch;

use crate::MobileMeshError;
use crate::app_core::policy::MANAGEMENT_BACKSTOP_MS;
use crate::app_core::worker::Worker;
use crate::app_core::{MobileAppError, mesh_error};
use crate::mobile_mesh::{
    MobileMeshManagementAnswerRecord, MobileMeshManagementEventRecord, MobileMeshManagementOutcome,
    MobileMeshPropertyWriteRecord, MobileMeshSession,
};

/// A cancel for one queue entry's exchanges.
pub(super) struct Operation {
    cancelled: watch::Sender<bool>,
}

impl Operation {
    pub(super) fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            cancelled: watch::Sender::new(false),
        })
    }

    /// Stop the entry: an exchange not yet sent never is, and one on the
    /// air fails with `Cancelled` at once. The device may still act on
    /// what it already has.
    pub(super) fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    pub(super) fn check(&self) -> Result<(), MobileAppError> {
        if *self.cancelled.borrow() {
            return Err(MobileAppError::Cancelled);
        }
        Ok(())
    }

    pub(super) async fn wait_cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        let _ = cancelled.wait_for(|cancelled| *cancelled).await;
    }
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
    pub(super) async fn exchange(
        &self,
        operation: &Operation,
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
            event = self.await_management(id, deadline) => event?,
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

    /// Write properties on the device at `address`, live until a save, in
    /// as many rounds as its answers need. Each answer echoes what the
    /// device kept.
    pub(super) async fn write_in_rounds(
        &self,
        operation: &Operation,
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
