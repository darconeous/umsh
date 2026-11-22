//! Commands waiting on the session's reports: pings and remote management,
//! keyed by the session's operation IDs.
//!
//! A waiter ends with its report, when the radio leaves attached or
//! configuring, when the session ends, or at a deadline of its own, so a
//! report the session dropped cannot hang one.

use std::collections::HashMap;

use tokio::sync::oneshot;

use super::MobileAppError;
use super::worker::Worker;
use crate::mobile_mesh::{
    MobileMeshManagementEventRecord, MobileMeshManagementOutcome, MobileMeshPingEventRecord,
};

type Answer<T> = oneshot::Sender<Result<T, MobileAppError>>;

#[derive(Default)]
pub(super) struct Waiters {
    pings: HashMap<u64, Answer<MobileMeshPingEventRecord>>,
    management: HashMap<u64, Answer<MobileMeshManagementEventRecord>>,
}

impl Worker {
    /// Wait for ping `id`'s report, or until `deadline_ms` on the
    /// monotonic clock.
    pub(super) async fn await_ping(
        &self,
        id: u64,
        deadline_ms: i64,
    ) -> Result<MobileMeshPingEventRecord, MobileAppError> {
        let (answer, report) = oneshot::channel();
        self.waiters.borrow_mut().pings.insert(id, answer);
        tokio::select! {
            report = report => report.unwrap_or(Err(MobileAppError::NoRadio)),
            () = self.clock.sleep_until(deadline_ms) => {
                self.waiters.borrow_mut().pings.remove(&id);
                Err(MobileAppError::NoAnswer)
            }
        }
    }

    /// Wait for management operation `id`'s ending, or until
    /// `deadline_ms` on the monotonic clock.
    pub(super) async fn await_management(
        &self,
        id: u64,
        deadline_ms: i64,
    ) -> Result<MobileMeshManagementEventRecord, MobileAppError> {
        let (answer, report) = oneshot::channel();
        self.waiters.borrow_mut().management.insert(id, answer);
        tokio::select! {
            report = report => report.unwrap_or(Err(MobileAppError::NoRadio)),
            () = self.clock.sleep_until(deadline_ms) => {
                self.waiters.borrow_mut().management.remove(&id);
                if let Some(session) = self.session() {
                    let _ = session.cancel_management(id);
                }
                Err(MobileAppError::NoAnswer)
            }
        }
    }

    /// Stop waiting on management operation `id`, and stop the session
    /// from sending it; the caller cancelled. The session ignores a cancel
    /// for an operation that has ended.
    pub(super) fn abandon_management(&self, id: u64) {
        self.waiters.borrow_mut().management.remove(&id);
        if let Some(session) = self.session() {
            let _ = session.cancel_management(id);
        }
    }

    pub(super) fn ping_event(&self, event: MobileMeshPingEventRecord) {
        let waiter = self.waiters.borrow_mut().pings.remove(&event.operation_id);
        if let Some(answer) = waiter {
            let _ = answer.send(Ok(event));
        }
    }

    pub(super) fn management_event(&self, event: MobileMeshManagementEventRecord) {
        // Progress ends nothing.
        if event.outcome == MobileMeshManagementOutcome::Progress {
            return;
        }
        let waiter = self
            .waiters
            .borrow_mut()
            .management
            .remove(&event.operation_id);
        if let Some(answer) = waiter {
            let _ = answer.send(Ok(event));
        }
    }

    /// The radio, or the session, is gone: every waiter fails with `error`,
    /// and the session frees each device's management queue.
    pub(super) fn fail_waiters(&self, error: &MobileAppError) {
        let Waiters { pings, management } = std::mem::take(&mut *self.waiters.borrow_mut());
        for (_, answer) in pings {
            let _ = answer.send(Err(error.clone()));
        }
        let session = self.session();
        for (id, answer) in management {
            if let Some(session) = &session {
                let _ = session.cancel_management(id);
            }
            let _ = answer.send(Err(error.clone()));
        }
    }
}
