//! `start`, `erase`, `stop` and `use_radio`: the only places the session
//! and the driver change. Each holds the worker's transition lock, so they
//! run whole and in turn.

use std::rc::Rc;
use std::sync::Arc;

use super::MobileAppError;
use super::records::{MobileAppChangesRecord, MobileAppLifecycle, MobileAppStartFailure};
use super::worker::{SessionWake, Worker};
use crate::radio_driver::{MobileRadioDriver, MobileRadioError, MobileRadioStateRecord};
use crate::{MobileCounterStore, MobileIdentity, MobileMeshSession};

impl Worker {
    /// Bring `identity` up. See `MobileAppCore::start`.
    pub(super) async fn start(
        self: &Rc<Self>,
        identity: Arc<MobileIdentity>,
    ) -> Result<(), MobileAppError> {
        self.may_transition(true)?;
        let _transition = self.transitions.lock().await;
        self.may_transition(true)?;

        let address = identity.public_identity().canonical_address;
        let host_key = crate::public_identity_bytes(address.clone())?;
        self.shared.enter(MobileAppLifecycle::Starting);
        self.reset_session_state();
        self.set_owner(Some(address.clone()));

        // 1. The host key, so a radio already linked can attach.
        if let Some(driver) = self.driver()
            && let Err(error) = driver.core_set_host_key(Some(host_key))
        {
            if error == MobileRadioError::Stopped {
                self.lose_driver(&driver);
            } else {
                log::error!(error:? = error; "the radio refused this phone's key");
                return Err(self.fail_start(MobileAppStartFailure::HostKey).await);
            }
        }

        // 2. The session, over counters of its own.
        let counter_store = match MobileCounterStore::new(self.config.counter_directory.clone()) {
            Ok(store) => store,
            Err(error) => {
                log::error!(error:? = error; "the counter store would not open");
                return Err(self.fail_start(MobileAppStartFailure::Session).await);
            }
        };
        *self.counter_store.borrow_mut() = Some(counter_store.clone());
        let session = match self.build_session(identity, counter_store).await {
            Ok(session) => session,
            Err(error) => {
                log::error!(error:? = error; "the mesh session would not start");
                return Err(self.fail_start(MobileAppStartFailure::Session).await);
            }
        };
        session.hold(Arc::new(SessionWake(self.signals.clone())));
        *self.session.borrow_mut() = Some(session.clone());

        // 3. The store's start-of-session repairs.
        if let Err(error) = self.repair_store(&address) {
            log::error!(error:? = error; "the store's start-of-session repairs failed");
            return Err(self.fail_start(MobileAppStartFailure::Store).await);
        }

        // 4–7. Everything the session needs before it hears anything.
        self.bootstrap(&address).await;

        // 8. Only now does the radio's traffic reach the session: frames it
        // held for one are understood, and channels are registered.
        if let Some(driver) = self.driver()
            && driver.core_use_mesh_session(Some(session)).await.is_err()
        {
            self.lose_driver(&driver);
        }

        self.shared.enter(MobileAppLifecycle::Running);
        // Whatever the session reported while starting.
        self.signals.raise_session();
        self.policy_triggered();
        // A radio that attached before the session existed found nothing
        // to open the meet on.
        self.settle_meet();
        Ok(())
    }

    /// Take the identity down. See `MobileAppCore::erase`.
    pub(super) async fn erase(self: &Rc<Self>, also_content: bool) -> Result<(), MobileAppError> {
        self.may_transition(false)?;
        let _transition = self.transitions.lock().await;
        self.may_transition(false)?;

        self.shared.enter(MobileAppLifecycle::Erasing);
        if let Some(driver) = self.driver()
            && driver.core_set_host_key(None).is_err()
        {
            self.lose_driver(&driver);
        }
        self.take_session_down().await;
        self.commands_settled().await;

        let result = self.remove_identity_data(also_content);
        // A reading taken for the old identity is not the next one's.
        self.settings.borrow_mut().position = None;
        self.set_owner(None);
        self.reset_session_state();
        self.shared.enter(MobileAppLifecycle::Idle);
        result
    }

    /// Finish the core. See `MobileAppCore::stop`.
    pub(super) async fn stop(self: &Rc<Self>) {
        let _transition = self.transitions.lock().await;
        if self.lifecycle() == MobileAppLifecycle::Stopped {
            return;
        }
        self.shared.enter(MobileAppLifecycle::Stopping);
        self.take_session_down().await;
        if let Some(driver) = self.driver.borrow_mut().take() {
            driver.release_hold();
        }
        self.commands_settled().await;
        self.reset_session_state();
        self.finish();
    }

    /// Carry the mesh over `driver`, or over none. See
    /// `MobileAppCore::use_radio`.
    pub(super) async fn use_radio(
        self: &Rc<Self>,
        driver: Option<Arc<MobileRadioDriver>>,
    ) -> Result<(), MobileAppError> {
        Self::may_use_radio(self.lifecycle())?;
        let _transition = self.transitions.lock().await;
        Self::may_use_radio(self.lifecycle())?;
        let previous = self.driver();
        if let (Some(previous), Some(next)) = (&previous, &driver)
            && Arc::ptr_eq(previous, next)
        {
            return Ok(());
        }
        if let Some(previous) = previous {
            // The leaving path fails what the radio held for the session;
            // what it holds afterward waits for whoever comes next.
            if self.session().is_some() {
                let _ = previous.core_use_mesh_session(None).await;
            }
            previous.release_hold();
        }
        *self.driver.borrow_mut() = None;
        // A swap is a detach: waiters fail, the claim's age restarts, the
        // gates reset, and the meet closes.
        self.radio_state(None);

        if let Some(driver) = driver {
            let signals = self.signals.clone();
            driver.hold(Arc::new(move || signals.raise_driver()));
            *self.driver.borrow_mut() = Some(driver.clone());
            if self.lifecycle() == MobileAppLifecycle::Running
                && let Some(session) = self.session()
            {
                let installed = match self.owner() {
                    Some(owner) => crate::public_identity_bytes(owner)
                        .ok()
                        .is_none_or(|key| driver.core_set_host_key(Some(key)).is_ok()),
                    None => true,
                };
                if !installed || driver.core_use_mesh_session(Some(session)).await.is_err() {
                    self.lose_driver(&driver);
                }
            }
        }
        self.policy_triggered();
        Ok(())
    }

    /// Whether `use_radio` may run now: in every state but the end, since
    /// a driver held by a core that is finishing would never be released.
    fn may_use_radio(lifecycle: MobileAppLifecycle) -> Result<(), MobileAppError> {
        match lifecycle {
            MobileAppLifecycle::Stopping | MobileAppLifecycle::Stopped => {
                Err(MobileAppError::Stopped)
            }
            _ => Ok(()),
        }
    }

    /// Whether `start` (or, when not, `erase`) may run now.
    fn may_transition(&self, starting: bool) -> Result<(), MobileAppError> {
        match self.lifecycle() {
            MobileAppLifecycle::Idle | MobileAppLifecycle::Failed { .. } => Ok(()),
            MobileAppLifecycle::Running if !starting => Ok(()),
            MobileAppLifecycle::Stopped => Err(MobileAppError::Stopped),
            MobileAppLifecycle::Starting
            | MobileAppLifecycle::Running
            | MobileAppLifecycle::Erasing
            | MobileAppLifecycle::Stopping => Err(MobileAppError::Busy),
        }
    }

    /// Set whose rows the queries read, raising every list.
    pub(super) fn set_owner(&self, owner: Option<String>) {
        self.shared.publish(|snapshot| {
            snapshot.owner = owner;
            MobileAppChangesRecord {
                peers_changed: true,
                channels_changed: true,
                conversations_changed: true,
                ..MobileAppChangesRecord::default()
            }
        });
    }

    #[cfg(not(test))]
    async fn build_session(
        &self,
        identity: Arc<MobileIdentity>,
        counter_store: Arc<MobileCounterStore>,
    ) -> Result<Arc<MobileMeshSession>, crate::MobileMeshError> {
        MobileMeshSession::start(identity, counter_store).await
    }

    #[cfg(test)]
    async fn build_session(
        &self,
        identity: Arc<MobileIdentity>,
        counter_store: Arc<MobileCounterStore>,
    ) -> Result<Arc<MobileMeshSession>, crate::MobileMeshError> {
        if self.virtual_time {
            MobileMeshSession::start_on_virtual_time(identity, counter_store).await
        } else {
            MobileMeshSession::start(identity, counter_store).await
        }
    }

    /// Fail `start` with `reason`: the session, if one was made, is shut
    /// down, and the lifecycle says why.
    async fn fail_start(self: &Rc<Self>, reason: MobileAppStartFailure) -> MobileAppError {
        self.take_session_down().await;
        self.reset_session_state();
        self.shared.enter(MobileAppLifecycle::Failed { reason });
        MobileAppError::StartFailed { reason }
    }

    /// Withdraw the session from the radio, then shut it and its counter
    /// store down, waiting for each thread. Waiters on the session fail.
    async fn take_session_down(self: &Rc<Self>) {
        let session = self.session.borrow_mut().take();
        if session.is_some()
            && let Some(driver) = self.driver()
            && driver.core_use_mesh_session(None).await.is_err()
        {
            self.lose_driver(&driver);
        }
        self.session_ended();
        if let Some(session) = session {
            session.shutdown().await;
        }
        let counter_store = self.counter_store.borrow_mut().take();
        if let Some(counter_store) = counter_store {
            counter_store.shutdown().await;
        }
    }

    /// What `erase` removes once the session is gone. Each part is tried;
    /// the first failure is reported.
    fn remove_identity_data(&self, also_content: bool) -> Result<(), MobileAppError> {
        let vault = self.vault.delete_all().map_err(|error| {
            log::error!(error:? = error; "the vault would not forget the channel keys");
            MobileAppError::Vault { error }
        });
        let counters = match std::fs::remove_dir_all(&self.config.counter_directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                log::error!(error:? = error.kind(); "the counter reservations would not go");
                Err(MobileAppError::CountersNotRemoved)
            }
        };
        let content = if also_content {
            self.store.erase_all_content().map_err(MobileAppError::from)
        } else {
            Ok(())
        };
        vault.and(counters).and(content)
    }

    /// The driver answered `Stopped`: it is gone, which is a detach.
    pub(super) fn lose_driver(self: &Rc<Self>, driver: &Arc<MobileRadioDriver>) {
        let current = self.driver();
        if current.is_some_and(|current| Arc::ptr_eq(&current, driver)) {
            log::warn!("the radio driver has stopped; carrying the mesh over none");
            *self.driver.borrow_mut() = None;
            self.radio_state(None);
        }
    }

    /// Report the attached radio's state, or that there is none.
    pub(super) fn radio_changed(&self, state: Option<MobileRadioStateRecord>) {
        let reported = state.clone().unwrap_or_else(MobileRadioStateRecord::idle);
        self.shared.publish(|snapshot| {
            snapshot.radio = state;
            MobileAppChangesRecord {
                radio: Some(reported),
                ..MobileAppChangesRecord::default()
            }
        });
        self.radio_policy_changed();
    }

    /// Forget what the old session left: its forward-secret conversations,
    /// its meet, its policy gates and per-attach flags.
    fn reset_session_state(&self) {
        self.shared.publish(|snapshot| {
            snapshot.forward_secret_conversations.clear();
            MobileAppChangesRecord {
                forward_secret_conversations: Some(Vec::new()),
                ..MobileAppChangesRecord::default()
            }
        });
        self.channels.borrow_mut().clear();
        self.reset_policy();
    }
}
